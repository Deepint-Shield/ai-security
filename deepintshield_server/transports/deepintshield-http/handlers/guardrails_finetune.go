package handlers

// Guardrail fine-tuning surface.
//
// Two paths shipped here, both workspace-scoped:
//
//   1. Regex extraction - accepts a CSV of labelled text (text + label columns,
//      optional category column) and derives literal-phrase patterns that the
//      operator can drop into a workspace policy's CustomPattern / CustomTerms.
//      Runs in-process, sub-second for normal corpus sizes (<10k rows). This
//      is the fast path that's wired up today.
//
//   2. LoRA fine-tune (scaffolded) - accepts the same CSV plus a base-model
//      identifier and would enqueue a training job that produces an adapter
//      loadable by the deepintshield_models sidecar. The endpoint is reserved
//      here so the UI's fine-tune form has a stable contract to talk to. The
//      response is currently a 202 with a placeholder job_id; a job runner
//      service is the missing piece (out-of-scope for this turn).
//
// Why both surfaces live in one file: they share schema-validation logic,
// CSV parsing, and the same auth + audit-context wrapping. Keeping them
// together means a future refactor that swaps regex extraction for an
// embedding-clustering approach only needs to touch one file.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// Persistence: the ring buffer + CSVs are mirrored to /app/data on every
// mutation so jobs survive a container rebuild. The mounted volume already
// exists (see docker-compose) so no infra change is required - just a
// JSON snapshot file. Reads happen exactly once at package init.
func finetuneStateDir() string {
	if d := strings.TrimSpace(os.Getenv("DEEPINT_FINETUNE_STATE_DIR")); d != "" {
		return d
	}
	return "/app/data/finetune"
}

func finetuneStatePath() string { return filepath.Join(finetuneStateDir(), "jobs.json") }
func finetuneCSVDir() string    { return filepath.Join(finetuneStateDir(), "csv") }
func finetuneCSVPath(id string) string {
	return filepath.Join(finetuneCSVDir(), id+".csv")
}

// finetuneJobRegistry keeps a small ring buffer of recently-submitted
// fine-tune jobs in memory so the UI has something concrete to render in
// its "recent jobs" panel even though the actual runner isn't wired up
// yet. When the runner ships, this in-memory cache can be replaced with a
// proper DB-backed table - the response shape stays the same. The cap
// keeps an idle dev box from accumulating thousands of placeholder rows
// across long-running sessions.
const finetuneJobRingCap = 50

type finetuneJobRecord struct {
	JobID          string    `json:"job_id"`
	Status         string    `json:"status"`
	BaseModel      string    `json:"base_model"`
	RowCount       int       `json:"row_count"`
	CreatedAt      time.Time `json:"created_at"`
	Message        string    `json:"message"`
	WorkspaceID    string    `json:"workspace_id,omitempty"`
	CheckpointPath string    `json:"checkpoint_path,omitempty"`
	FinalLoss      float64   `json:"final_loss,omitempty"`
	Progress       float64   `json:"progress,omitempty"`
	DeployedOn     string    `json:"deployed_on,omitempty"` // detector_name once the operator hits Deploy
	HasCSV         bool      `json:"has_csv,omitempty"`     // true once the original training CSV is cached
}

var (
	finetuneInitOnce sync.Once
	finetuneJobMu    sync.RWMutex
	finetuneJobLog   []finetuneJobRecord
	// finetuneCSVs stores the training CSV per job so operators can download
	// the exact data a fine-tune ran on from the "Recent jobs" table. Sized
	// to match the job ring (50 entries) and capped per-entry at 5 MB so a
	// pathological upload can't balloon resident memory. Eviction mirrors
	// the ring: when a job_id falls out of finetuneJobLog its CSV goes too.
	finetuneCSVMu sync.RWMutex
	finetuneCSVs  = make(map[string]string, finetuneJobRingCap)
)

const finetuneCSVMaxBytes = 5 * 1024 * 1024

func storeFinetuneCSV(jobID, csv string) {
	if jobID == "" || csv == "" {
		return
	}
	if len(csv) > finetuneCSVMaxBytes {
		csv = csv[:finetuneCSVMaxBytes]
	}
	finetuneCSVMu.Lock()
	finetuneCSVs[jobID] = csv
	finetuneCSVMu.Unlock()
	// Persist to disk so a server rebuild doesn't lose the corpus the
	// operator originally uploaded.
	_ = os.MkdirAll(finetuneCSVDir(), 0o755)
	_ = os.WriteFile(finetuneCSVPath(jobID), []byte(csv), 0o644)
}

func getFinetuneCSV(jobID string) (string, bool) {
	finetuneCSVMu.RLock()
	csv, ok := finetuneCSVs[jobID]
	finetuneCSVMu.RUnlock()
	if ok {
		return csv, true
	}
	// Cold-path fallback - the in-memory cache may have been bypassed on
	// startup (e.g. tests). Read straight from disk.
	if data, err := os.ReadFile(finetuneCSVPath(jobID)); err == nil {
		finetuneCSVMu.Lock()
		finetuneCSVs[jobID] = string(data)
		finetuneCSVMu.Unlock()
		return string(data), true
	}
	return "", false
}

func evictFinetuneCSVs(keep []finetuneJobRecord) {
	live := make(map[string]struct{}, len(keep))
	for _, r := range keep {
		live[r.JobID] = struct{}{}
	}
	finetuneCSVMu.Lock()
	for id := range finetuneCSVs {
		if _, ok := live[id]; !ok {
			delete(finetuneCSVs, id)
			_ = os.Remove(finetuneCSVPath(id))
		}
	}
	finetuneCSVMu.Unlock()
}

// loadFinetuneState reads the JSON snapshot + cached CSVs back into memory
// on first access. Idempotent via finetuneInitOnce.
func loadFinetuneState() {
	finetuneInitOnce.Do(func() {
		data, err := os.ReadFile(finetuneStatePath())
		if err != nil {
			return
		}
		var records []finetuneJobRecord
		if json.Unmarshal(data, &records) != nil {
			return
		}
		finetuneJobMu.Lock()
		finetuneJobLog = records
		finetuneJobMu.Unlock()
		// Warm CSV cache from disk so the "Download CSV" button works
		// without a per-row hit on first render.
		entries, err := os.ReadDir(finetuneCSVDir())
		if err != nil {
			return
		}
		finetuneCSVMu.Lock()
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".csv") {
				continue
			}
			id := strings.TrimSuffix(name, ".csv")
			if body, err := os.ReadFile(filepath.Join(finetuneCSVDir(), name)); err == nil {
				finetuneCSVs[id] = string(body)
			}
		}
		finetuneCSVMu.Unlock()
	})
}

// persistFinetuneJobs writes the current ring to /app/data. Called after
// every mutation; the file is tiny so we just rewrite it whole.
func persistFinetuneJobs(snapshot []finetuneJobRecord) {
	if err := os.MkdirAll(finetuneStateDir(), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	tmp := finetuneStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, finetuneStatePath())
}

func recordFinetuneJob(record finetuneJobRecord) {
	loadFinetuneState()
	finetuneJobMu.Lock()
	finetuneJobLog = append(finetuneJobLog, record)
	if len(finetuneJobLog) > finetuneJobRingCap {
		// Drop the oldest entries - the ring is intentionally tiny so a
		// trimmed copy beats the maintenance complexity of a linked list.
		finetuneJobLog = append([]finetuneJobRecord(nil), finetuneJobLog[len(finetuneJobLog)-finetuneJobRingCap:]...)
	}
	snapshot := append([]finetuneJobRecord(nil), finetuneJobLog...)
	finetuneJobMu.Unlock()
	evictFinetuneCSVs(snapshot)
	persistFinetuneJobs(snapshot)
}

func listFinetuneJobs() []finetuneJobRecord {
	loadFinetuneState()
	finetuneJobMu.RLock()
	defer finetuneJobMu.RUnlock()
	out := make([]finetuneJobRecord, len(finetuneJobLog))
	for i, entry := range finetuneJobLog {
		// Newest first - operators glance at the top of the list.
		out[len(finetuneJobLog)-1-i] = entry
	}
	return out
}

// finetuneRegexExtractRequest is the JSON body for the regex-extraction
// endpoint. CSV content is passed inline as text rather than multipart so
// the UI doesn't have to negotiate file uploads on top of its existing
// fetch-based API surface - the corpus sizes this path is designed for
// (under a few MB) fit comfortably in JSON.
type finetuneRegexExtractRequest struct {
	CSVText     string `json:"csv_text"`
	TextColumn  string `json:"text_column"`  // optional override; default "text"
	LabelColumn string `json:"label_column"` // optional override; default "label"
	CategoryCol string `json:"category_col"` // optional override; default "category"
	MinSupport  int    `json:"min_support"`  // min positive rows containing a candidate; default 2
	MaxPatterns int    `json:"max_patterns"` // upper bound on extracted patterns per category; default 25
}

// finetuneExtractedPattern is a single literal phrase that surfaced as a
// strong signal for a category. Confidence approximates P(category | phrase
// appears) computed from the corpus, support is the absolute count of
// positive rows that contained the phrase.
type finetuneExtractedPattern struct {
	Category   string  `json:"category"`
	Phrase     string  `json:"phrase"` // raw literal - useful for CustomTerms
	Regex      string  `json:"regex"`  // word-boundary-quoted regex form for CustomPattern
	Support    int     `json:"support"`
	Confidence float64 `json:"confidence"`
}

type finetuneRegexExtractResponse struct {
	Patterns      []finetuneExtractedPattern `json:"patterns"`
	RowCount      int                        `json:"row_count"`
	PositiveCount int                        `json:"positive_count"`
	Warnings      []string                   `json:"warnings"`
}

// finetuneLoRARequest is the JSON body for the LoRA fine-tune endpoint.
// The runner that consumes these jobs is not implemented yet; today the
// endpoint records the request and returns a placeholder job_id so the UI
// can render an "enqueued" state.
type finetuneLoRARequest struct {
	CSVText     string `json:"csv_text"`
	TextColumn  string `json:"text_column"`
	LabelColumn string `json:"label_column"`
	CategoryCol string `json:"category_col"`
	BaseModel   string `json:"base_model"` // HF model id of the classifier to LoRA on top of
}

type finetuneLoRAResponse struct {
	JobID     string    `json:"job_id"`
	Status    string    `json:"status"` // "queued" - never advances today
	CreatedAt time.Time `json:"created_at"`
	Message   string    `json:"message"`
}

// extractRegexFromCSV implements the regex-extraction algorithm. The
// approach is intentionally simple - we count how often each non-trivial
// n-gram (length 1..3 word tokens) appears in positive rows for a given
// category, then filter by support and a precision proxy (the fraction of
// rows containing the phrase that share the category). This produces
// patterns that are obviously good without the false-positive risk of a
// fully unsupervised generator.
func extractRegexFromCSV(payload finetuneRegexExtractRequest) (finetuneRegexExtractResponse, error) {
	reader := csv.NewReader(strings.NewReader(payload.CSVText))
	reader.LazyQuotes = true
	header, err := reader.Read()
	if err != nil {
		return finetuneRegexExtractResponse{}, fmt.Errorf("failed to read CSV header: %w", err)
	}
	headerIdx := make(map[string]int, len(header))
	for i, name := range header {
		headerIdx[strings.ToLower(strings.TrimSpace(name))] = i
	}
	textCol := strings.ToLower(strings.TrimSpace(payload.TextColumn))
	if textCol == "" {
		textCol = "text"
	}
	labelCol := strings.ToLower(strings.TrimSpace(payload.LabelColumn))
	if labelCol == "" {
		labelCol = "label"
	}
	catCol := strings.ToLower(strings.TrimSpace(payload.CategoryCol))
	if catCol == "" {
		catCol = "category"
	}
	textIdx, hasText := headerIdx[textCol]
	labelIdx, hasLabel := headerIdx[labelCol]
	if !hasText || !hasLabel {
		return finetuneRegexExtractResponse{}, fmt.Errorf("CSV must contain %q and %q columns", textCol, labelCol)
	}
	categoryIdx, hasCategory := headerIdx[catCol]

	minSupport := payload.MinSupport
	if minSupport <= 0 {
		minSupport = 2
	}
	maxPatterns := payload.MaxPatterns
	if maxPatterns <= 0 {
		maxPatterns = 25
	}

	type ngramStats struct {
		PositiveByCat map[string]int
		Negative      int
	}
	stats := make(map[string]*ngramStats)
	categories := make(map[string]int) // total positive rows per category
	rowCount := 0
	positiveCount := 0
	warnings := make([]string, 0, 4)

	for {
		row, readErr := reader.Read()
		if readErr != nil {
			break
		}
		rowCount++
		if textIdx >= len(row) || labelIdx >= len(row) {
			warnings = append(warnings, fmt.Sprintf("row %d: missing required column, skipped", rowCount))
			continue
		}
		text := strings.TrimSpace(row[textIdx])
		if text == "" {
			continue
		}
		isPositive := normalizeLabel(row[labelIdx])
		category := ""
		if hasCategory && categoryIdx < len(row) {
			category = strings.TrimSpace(row[categoryIdx])
		}
		if category == "" {
			category = "default"
		}
		if isPositive {
			positiveCount++
			categories[category]++
		}
		for _, ngram := range extractNgrams(text, 1, 3) {
			entry, ok := stats[ngram]
			if !ok {
				entry = &ngramStats{PositiveByCat: make(map[string]int)}
				stats[ngram] = entry
			}
			if isPositive {
				entry.PositiveByCat[category]++
			} else {
				entry.Negative++
			}
		}
	}

	out := make([]finetuneExtractedPattern, 0, maxPatterns*len(categories))
	for ngram, entry := range stats {
		for category, support := range entry.PositiveByCat {
			if support < minSupport {
				continue
			}
			totalOccurrences := support + entry.Negative
			// Cross-category positives shouldn't depress precision for this
			// category - phrases that signal multiple categories are still
			// useful so long as they're rare in negatives.
			confidence := float64(support) / float64(totalOccurrences)
			if confidence < 0.6 {
				// Skip phrases that fire frequently outside their category;
				// they're too noisy to be useful as guardrail patterns.
				continue
			}
			out = append(out, finetuneExtractedPattern{
				Category:   category,
				Phrase:     ngram,
				Regex:      ngramToRegex(ngram),
				Support:    support,
				Confidence: round4(confidence),
			})
		}
	}

	// Sort by (category, -confidence, -support) so the UI surfaces the
	// strongest signals per category first, and trim to maxPatterns per
	// category to keep the response payload bounded.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Support > out[j].Support
	})
	filtered := make([]finetuneExtractedPattern, 0, len(out))
	perCategory := make(map[string]int, len(categories))
	for _, pattern := range out {
		if perCategory[pattern.Category] >= maxPatterns {
			continue
		}
		filtered = append(filtered, pattern)
		perCategory[pattern.Category]++
	}

	if positiveCount == 0 {
		warnings = append(warnings, "no rows labelled positive - extraction returns no patterns")
	}
	if len(filtered) == 0 && positiveCount > 0 {
		warnings = append(warnings, fmt.Sprintf("no n-gram met support>=%d and precision>=0.6 - try a larger corpus or lower min_support", minSupport))
	}

	return finetuneRegexExtractResponse{
		Patterns:      filtered,
		RowCount:      rowCount,
		PositiveCount: positiveCount,
		Warnings:      warnings,
	}, nil
}

// normalizeLabel maps the common positive/negative label conventions onto
// a single bool. "1", "true", "positive", "pos", "yes", "y" → positive.
// Everything else → negative. Mixed-case + whitespace tolerated because
// real CSV exports are messy.
func normalizeLabel(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "positive", "pos", "yes", "y", "harmful", "block", "deny":
		return true
	}
	return false
}

// extractNgrams emits 1..n-token n-grams from the input text. Tokens are
// lowercased + stripped of leading/trailing punctuation so the same phrase
// in different sentences shares a stats entry. Pure-numeric tokens get
// dropped - they don't make useful guardrail patterns and they inflate the
// candidate set.
func extractNgrams(text string, minLen, maxLen int) []string {
	clean := strings.ToLower(text)
	tokens := strings.Fields(clean)
	stripped := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		trimmed := strings.Trim(tok, ".,!?;:\"()[]{}'`")
		if trimmed == "" || isAllDigits(trimmed) {
			continue
		}
		stripped = append(stripped, trimmed)
	}
	out := make([]string, 0, len(stripped)*maxLen)
	for n := minLen; n <= maxLen; n++ {
		for i := 0; i+n <= len(stripped); i++ {
			ngram := strings.Join(stripped[i:i+n], " ")
			if len(ngram) < 3 || len(ngram) > 80 {
				continue
			}
			out = append(out, ngram)
		}
	}
	return out
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// ngramToRegex wraps a literal phrase in word boundaries and quotes any
// regex metacharacters so the output can drop straight into a policy's
// CustomPattern field. Spaces inside the phrase become `\s+` so the
// pattern survives variable whitespace in real prompts.
func ngramToRegex(ngram string) string {
	parts := strings.Fields(ngram)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	body := strings.Join(parts, `\s+`)
	return `(?i)\b` + body + `\b`
}

func round4(v float64) float64 {
	return float64(int(v*10000)) / 10000
}

// extractRegexHandler is the public route for the regex-extraction MVP.
// Workspace-scoped - the auth + tenant middleware that wraps this handler
// in RegisterRoutes is the same one used by every other guardrail route.
func (h *GuardrailsHandler) extractRegexFromCSV(ctx *fasthttp.RequestCtx) {
	var payload finetuneRegexExtractRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if strings.TrimSpace(payload.CSVText) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "csv_text is required")
		return
	}
	response, err := extractRegexFromCSV(payload)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSON(ctx, response)
}

// modelsSidecarEndpoint returns the configured deepintshield_models endpoint
// (defaulting to the in-cluster compose service URL). The fine-tune flow
// reuses the same endpoint the eval-time adapter uses, so a single env
// override (DEEPINTSHIELD_MODELS_ENDPOINT) covers both.
func modelsSidecarEndpoint() string {
	v := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_MODELS_ENDPOINT"))
	if v == "" {
		v = "http://deepintshield-models:8093"
	}
	return strings.TrimRight(v, "/")
}

// csvTextToRows parses {text,label,category} CSV content into the row-dict
// shape the sidecar's /v1/finetune/run accepts. Quote-tolerant, label
// normalization deferred to the sidecar so the wire format stays simple.
func csvTextToRows(csvText, textCol, labelCol string) ([]map[string]any, int, error) {
	if textCol == "" {
		textCol = "text"
	}
	if labelCol == "" {
		labelCol = "label"
	}
	reader := csv.NewReader(strings.NewReader(csvText))
	reader.LazyQuotes = true
	header, err := reader.Read()
	if err != nil {
		return nil, 0, fmt.Errorf("read CSV header: %w", err)
	}
	idx := make(map[string]int, len(header))
	for i, name := range header {
		idx[strings.ToLower(strings.TrimSpace(name))] = i
	}
	tIdx, hasT := idx[strings.ToLower(textCol)]
	lIdx, hasL := idx[strings.ToLower(labelCol)]
	if !hasT || !hasL {
		return nil, 0, fmt.Errorf("CSV must contain %q and %q columns", textCol, labelCol)
	}
	out := make([]map[string]any, 0, 64)
	for {
		row, readErr := reader.Read()
		if readErr != nil {
			break
		}
		if tIdx >= len(row) || lIdx >= len(row) {
			continue
		}
		out = append(out, map[string]any{
			"text":  strings.TrimSpace(row[tIdx]),
			"label": strings.TrimSpace(row[lIdx]),
		})
	}
	return out, len(out), nil
}

// enqueueLoRAJob now actually triggers the sidecar's training runner.
// The HTTP submission returns immediately with status=queued; a background
// goroutine polls the sidecar's /v1/finetune/status/{job_id} and updates
// the in-memory record. The UI's existing "Recent fine-tune jobs" list
// surfaces the live status without any further plumbing.
func (h *GuardrailsHandler) enqueueLoRAJob(ctx *fasthttp.RequestCtx) {
	var payload finetuneLoRARequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if strings.TrimSpace(payload.CSVText) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "csv_text is required")
		return
	}
	if strings.TrimSpace(payload.BaseModel) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "base_model is required (HF model id)")
		return
	}
	// Parse CSV → rows + cheap schema validation.
	rows, rowCount, err := csvTextToRows(payload.CSVText, payload.TextColumn, payload.LabelColumn)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("CSV parse failed: %v", err))
		return
	}
	jobID := "lora-" + uuid.NewString()
	workspaceID := workspaceIDFromContext(ctx)
	// Record locally as queued so the UI sees the job even if the sidecar
	// call fails - the polling goroutine will flip it to failed if so.
	storeFinetuneCSV(jobID, payload.CSVText)
	recordFinetuneJob(finetuneJobRecord{
		JobID:       jobID,
		Status:      "queued",
		BaseModel:   strings.TrimSpace(payload.BaseModel),
		RowCount:    rowCount,
		CreatedAt:   time.Now().UTC(),
		Message:     "LoRA fine-tune submitted to deepintshield_models sidecar.",
		WorkspaceID: workspaceID,
		HasCSV:      true,
	})

	// Fire the sidecar call in a goroutine so the HTTP handler returns
	// immediately - the trainer runs for seconds to minutes depending on
	// row count + epoch budget.
	go func() {
		body, _ := json.Marshal(map[string]any{
			"workspace_id":  workspaceID,
			"base_model_id": strings.TrimSpace(payload.BaseModel),
			"training_rows": rows,
			"epochs":        3,
			"job_id":        jobID,
		})
		endpoint := modelsSidecarEndpoint() + "/v1/finetune/run"
		req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			updateJobStatus(jobID, "failed", "sidecar submit failed: "+err.Error(), nil)
			return
		}
		defer resp.Body.Close()
		var initial map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&initial)
		updateJobStatus(jobID, "running", "Training in progress on the sidecar.", initial)

		// Poll status every 3 s until terminal. Keep this bounded - a
		// hung sidecar shouldn't peg the goroutine forever.
		statusEndpoint := modelsSidecarEndpoint() + "/v1/finetune/status/" + jobID
		deadline := time.Now().Add(30 * time.Minute)
		pollClient := &http.Client{Timeout: 10 * time.Second}
		for time.Now().Before(deadline) {
			time.Sleep(3 * time.Second)
			pollResp, perr := pollClient.Get(statusEndpoint)
			if perr != nil {
				continue
			}
			var s map[string]any
			_ = json.NewDecoder(pollResp.Body).Decode(&s)
			pollResp.Body.Close()
			status, _ := s["status"].(string)
			msg := ""
			if v, ok := s["error"].(string); ok && v != "" {
				msg = v
			}
			updateJobStatus(jobID, status, msg, s)
			if status == "succeeded" || status == "failed" {
				return
			}
		}
		updateJobStatus(jobID, "failed", "training timeout", nil)
	}()

	SendJSON(ctx, finetuneLoRAResponse{
		JobID:     jobID,
		Status:    "queued",
		CreatedAt: time.Now().UTC(),
		Message:   "LoRA fine-tune submitted.",
	})
}

// updateJobStatus mutates the in-memory ring's record matching job_id.
// Caller may pass the sidecar's full status payload via extras; we lift
// checkpoint_path / final_loss / progress out so the UI doesn't have to
// understand the sidecar's JSON.
func updateJobStatus(jobID, status, message string, extras map[string]any) {
	loadFinetuneState()
	finetuneJobMu.Lock()
	for i, rec := range finetuneJobLog {
		if rec.JobID != jobID {
			continue
		}
		if status != "" {
			finetuneJobLog[i].Status = status
		}
		if message != "" {
			finetuneJobLog[i].Message = message
		}
		if extras != nil {
			if v, ok := extras["checkpoint_path"].(string); ok && v != "" {
				finetuneJobLog[i].CheckpointPath = v
			}
			if v, ok := extras["final_loss"].(float64); ok {
				finetuneJobLog[i].FinalLoss = v
			}
			if v, ok := extras["progress"].(float64); ok {
				finetuneJobLog[i].Progress = v
			}
		}
		snapshot := append([]finetuneJobRecord(nil), finetuneJobLog...)
		finetuneJobMu.Unlock()
		persistFinetuneJobs(snapshot)
		return
	}
	finetuneJobMu.Unlock()
}

func workspaceIDFromContext(ctx *fasthttp.RequestCtx) string {
	// The workspace middleware stuffs the active workspace ID into the
	// fasthttp.RequestCtx user values under "workspace_id". When absent
	// (e.g. local dev without auth) fall back to "default".
	if v := ctx.UserValue("workspace_id"); v != nil {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return "default"
}

// deployLoRAJob applies the trained adapter for the given job onto the
// named detector in the sidecar registry. Subsequent /v1/evaluate calls
// route through the LoRA-merged classifier instead of the base model.
func (h *GuardrailsHandler) deployLoRAJob(ctx *fasthttp.RequestCtx) {
	var payload struct {
		JobID        string `json:"job_id"`
		DetectorName string `json:"detector_name"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if strings.TrimSpace(payload.JobID) == "" || strings.TrimSpace(payload.DetectorName) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "job_id and detector_name are required")
		return
	}
	body, _ := json.Marshal(map[string]any{
		"job_id":        payload.JobID,
		"detector_name": payload.DetectorName,
	})
	endpoint := modelsSidecarEndpoint() + "/v1/finetune/deploy"
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("sidecar deploy failed: %v", err))
		return
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if status, _ := out["status"].(string); status == "deployed" {
		// Stamp the deployment on the in-memory job record so the UI badge
		// shows the active detector that's running the fine-tuned model.
		// "Only one model deployed at a time" - clear DeployedOn on every
		// other job pointing at the same detector before stamping this one,
		// so the UI shows exactly one live badge per detector slot. The
		// sidecar registry is already single-slot (the pipeline swap
		// atomically replaces whatever was there), so this just keeps the
		// audit trail in sync with what's actually running.
		loadFinetuneState()
		finetuneJobMu.Lock()
		var snapshot []finetuneJobRecord
		for i, rec := range finetuneJobLog {
			if rec.DeployedOn == payload.DetectorName && rec.JobID != payload.JobID {
				finetuneJobLog[i].DeployedOn = ""
			}
			if rec.JobID == payload.JobID {
				finetuneJobLog[i].DeployedOn = payload.DetectorName
			}
		}
		snapshot = append([]finetuneJobRecord(nil), finetuneJobLog...)
		finetuneJobMu.Unlock()
		if snapshot != nil {
			persistFinetuneJobs(snapshot)
		}
	}
	SendJSON(ctx, out)
}

// deleteLoRAJob removes a fine-tune job record + its on-disk checkpoint
// from the sidecar. When the job was the currently-live deployment, also
// posts /v1/finetune/reset so the detector's pipeline is rebuilt from the
// base model - the operator clicking Delete on the active job expects the
// detector to return to its default, not to keep serving the now-deleted
// adapter. CSV artifact is also evicted so the gateway side is clean.
func (h *GuardrailsHandler) deleteLoRAJob(ctx *fasthttp.RequestCtx) {
	jobID := strings.TrimSpace(string(ctx.QueryArgs().Peek("job_id")))
	if jobID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "job_id query parameter is required")
		return
	}
	// Snapshot the record before we drop it so we know whether to reset
	// the detector adapter on the sidecar.
	loadFinetuneState()
	finetuneJobMu.RLock()
	var liveDetector string
	for _, rec := range finetuneJobLog {
		if rec.JobID == jobID {
			liveDetector = rec.DeployedOn
			break
		}
	}
	finetuneJobMu.RUnlock()

	client := &http.Client{Timeout: 30 * time.Second}
	// 1) If this job is the currently-deployed one, reset the detector
	//    to its base-model pipeline before deleting the job artifacts.
	//    Order matters - reset first so the eval path stops serving the
	//    adapter before its checkpoint disappears.
	if liveDetector != "" {
		body, _ := json.Marshal(map[string]any{"detector_name": liveDetector})
		req, _ := http.NewRequest(http.MethodPost, modelsSidecarEndpoint()+"/v1/finetune/reset", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	// 2) Tell the sidecar to drop the on-disk checkpoint + in-memory job.
	//    Best-effort - a sidecar 5xx shouldn't block the gateway-side
	//    cleanup since the operator's intent is "remove this from my view".
	delReq, _ := http.NewRequest(http.MethodDelete, modelsSidecarEndpoint()+"/v1/finetune/jobs/"+jobID, nil)
	if resp, err := client.Do(delReq); err == nil {
		resp.Body.Close()
	}
	// 3) Drop the gateway-side record + cached CSV.
	finetuneJobMu.Lock()
	keep := finetuneJobLog[:0]
	for _, rec := range finetuneJobLog {
		if rec.JobID == jobID {
			continue
		}
		keep = append(keep, rec)
	}
	finetuneJobLog = keep
	snapshot := append([]finetuneJobRecord(nil), finetuneJobLog...)
	finetuneJobMu.Unlock()
	evictFinetuneCSVs(snapshot)
	persistFinetuneJobs(snapshot)

	SendJSON(ctx, map[string]any{
		"status":         "deleted",
		"job_id":         jobID,
		"reset_detector": liveDetector,
	})
}

// downloadFinetuneCSV streams back the original training CSV for a job_id.
// Used by the "Download CSV" button in the Recent jobs table so operators
// can audit the exact data a fine-tune ran on. 404s once the job ages out
// of the in-memory ring.
func (h *GuardrailsHandler) downloadFinetuneCSV(ctx *fasthttp.RequestCtx) {
	jobID := strings.TrimSpace(string(ctx.QueryArgs().Peek("job_id")))
	if jobID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "job_id query parameter is required")
		return
	}
	csv, ok := getFinetuneCSV(jobID)
	if !ok {
		SendError(ctx, fasthttp.StatusNotFound, "CSV for this job is no longer cached (aged out of the ring buffer)")
		return
	}
	ctx.Response.Header.Set("Content-Type", "text/csv; charset=utf-8")
	ctx.Response.Header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.csv\"", jobID))
	ctx.SetBodyString(csv)
}

// listFinetuneJobsHandler returns the in-memory ring of recently-submitted
// LoRA jobs. Newest first; capped at finetuneJobRingCap. The handler is
// workspace-scoped via the standard guardrails middleware chain - every
// caller's view is the same tenant-shared list today since the placeholder
// runner doesn't yet have a per-tenant queue.
func (h *GuardrailsHandler) listFinetuneJobsHandler(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, map[string]any{"jobs": listFinetuneJobs()})
}

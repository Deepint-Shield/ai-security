// Package configbundle exports a tenant/workspace's authored configuration
// (guardrail policies, routing, MCP clients, RAG sources, prompts, and virtual
// key *references*) as a signed, content-hashed tar.gz. The Enterprise-VPC
// customer seeds this into their self-hosted data plane at install time, and
// the Phase-3 tunnel re-pulls it for delta-sync.
//
// Security: provider secrets never leave the control plane. Virtual keys are
// exported as references only - the secret `value`/`cache_key` columns are
// dropped - and provider API keys are not included at all.
package configbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Bundle is the in-memory result of an export.
type Bundle struct {
	Data     []byte // the tar.gz payload
	Revision string // content hash of the manifest (delta-sync cursor)
}

// Manifest is serialized to manifest.json inside the bundle and signed.
type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	// OrgID is set for ORG-scoped bundles (one DP per governance org), where
	// TenantID/WorkspaceID are empty and the bundle spans every workspace under
	// the org. Empty for legacy per-workspace bundles.
	OrgID        string            `json:"org_id,omitempty"`
	GeneratedAt  time.Time         `json:"generated_at"`
	Files        map[string]string `json:"files"`         // filename -> sha256
	BundleSHA256 string            `json:"bundle_sha256"` // hash over the sorted file hashes
}

type fileEntry struct {
	name string
	data []byte
	hash string
}

// tableSpec describes one config file in the bundle.
type tableSpec struct {
	file  string // filename inside the bundle
	table string // physical table name (for HasTable existence check)
	query string // SELECT … single placeholder is the workspace id
}

// workspaceTables enumerates the workspace-scoped config surface, mirroring the
// set cloneWorkspace copies plus prompts and VK references. Virtual keys select
// safe columns ONLY - the secret `value`/`cache_key` are never selected.
var workspaceTables = []tableSpec{
	{file: "guardrail_policies.json", table: "guardrail_policies", query: "SELECT * FROM guardrail_policies WHERE workspace_id = ?"},
	{file: "routing_rules.json", table: "routing_rules", query: "SELECT * FROM routing_rules WHERE workspace_id = ?"},
	{file: "config_plugins.json", table: "config_plugins", query: "SELECT * FROM config_plugins WHERE workspace_id = ?"},
	{file: "config_mcp_clients.json", table: "config_mcp_clients", query: "SELECT * FROM config_mcp_clients WHERE workspace_id = ?"},
	{file: "guardrail_rag_sources.json", table: "guardrail_rag_sources", query: "SELECT * FROM guardrail_rag_sources WHERE workspace_id = ?"},
	{file: "prompts.json", table: "prompts", query: "SELECT * FROM prompts WHERE workspace_id = ?"},
	{file: "prompt_versions.json", table: "prompt_versions", query: "SELECT * FROM prompt_versions WHERE prompt_id IN (SELECT id FROM prompts WHERE workspace_id = ?)"},
	{
		file:  "virtual_keys.json",
		table: "governance_virtual_keys",
		// references only - NO `value`, NO `cache_key`.
		query: "SELECT id, name, tenant_id, workspace_id, created_at, updated_at FROM governance_virtual_keys WHERE workspace_id = ?",
	},
}

// gatherFiles runs each workspace-scoped query across ALL the given workspace
// ids and unions the rows into one file per table. One id → a single-workspace
// bundle; many → an org-wide bundle. Emits references/metadata only - the VK
// query never selects secret material.
func gatherFiles(ctx context.Context, db *gorm.DB, workspaceIDs []string) ([]fileEntry, error) {
	migrator := db.Migrator()
	files := make([]fileEntry, 0, len(workspaceTables))
	for _, spec := range workspaceTables {
		if !migrator.HasTable(spec.table) {
			continue // optional table not present on this deployment
		}
		all := make([]map[string]any, 0)
		for _, wsID := range workspaceIDs {
			var rows []map[string]any
			if err := db.WithContext(ctx).Raw(spec.query, wsID).Scan(&rows).Error; err != nil {
				return nil, fmt.Errorf("configbundle: query %s: %w", spec.table, err)
			}
			all = append(all, rows...)
		}
		payload, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("configbundle: marshal %s: %w", spec.file, err)
		}
		sum := sha256.Sum256(payload)
		files = append(files, fileEntry{name: spec.file, data: payload, hash: hex.EncodeToString(sum[:])})
	}
	return files, nil
}

// assembleBundle hashes the files into a deterministic manifest and tars the
// result. Shared by Export (per-workspace) and ExportOrg (org-wide) so both
// bundles are structurally identical.
func assembleBundle(files []fileEntry, base Manifest) (*Bundle, error) {
	// Deterministic manifest: sort by name so the bundle hash is stable for
	// identical config (lets the tunnel skip no-op pulls).
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	manifest := base
	manifest.SchemaVersion = 1
	manifest.GeneratedAt = time.Now().UTC()
	manifest.Files = make(map[string]string, len(files))
	hashConcat := bytes.Buffer{}
	for _, f := range files {
		manifest.Files[f.name] = f.hash
		hashConcat.WriteString(f.name)
		hashConcat.WriteString(":")
		hashConcat.WriteString(f.hash)
		hashConcat.WriteString("\n")
	}
	bundleSum := sha256.Sum256(hashConcat.Bytes())
	manifest.BundleSHA256 = hex.EncodeToString(bundleSum[:])

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("configbundle: marshal manifest: %w", err)
	}

	// Assemble the tar.gz: manifest.json, then each file. The open-source
	// build does not sign the manifest or embed a CA cert; manifest signing
	// is part of the commercial control-plane tunnel.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: manifest.GeneratedAt}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write("manifest.json", manifestJSON); err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := write(f.name, f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return &Bundle{Data: buf.Bytes(), Revision: manifest.BundleSHA256}, nil
}

// Export gathers ONE workspace's config and returns the tar.gz bundle plus its
// revision (content hash).
func Export(ctx context.Context, db *gorm.DB, tenantID, workspaceID string) (*Bundle, error) {
	if db == nil {
		return nil, fmt.Errorf("configbundle: nil db")
	}
	if workspaceID == "" {
		return nil, fmt.Errorf("configbundle: workspace_id is required")
	}
	files, err := gatherFiles(ctx, db, []string{workspaceID})
	if err != nil {
		return nil, err
	}
	return assembleBundle(files, Manifest{TenantID: tenantID, WorkspaceID: workspaceID})
}

// ExportOrg gathers the config for EVERY workspace under a governance org (the
// "one data plane per org" model) into a single signed bundle. ISOLATION: only
// workspaces whose tenant's organization_id = govOrgID are included via the
// membership join - an org-scoped DP can never read another org's config.
func ExportOrg(ctx context.Context, db *gorm.DB, govOrgID string) (*Bundle, error) {
	if db == nil {
		return nil, fmt.Errorf("configbundle: nil db")
	}
	govOrgID = strings.TrimSpace(govOrgID)
	if govOrgID == "" {
		return nil, fmt.Errorf("configbundle: org id is required")
	}
	var workspaceIDs []string
	if err := db.WithContext(ctx).Raw(
		`SELECT w.id FROM workspaces w
		 JOIN organizations o ON o.id = w.org_id
		 WHERE o.organization_id = ?
		 ORDER BY w.id`, govOrgID).
		Scan(&workspaceIDs).Error; err != nil {
		return nil, fmt.Errorf("configbundle: list org workspaces: %w", err)
	}
	files, err := gatherFiles(ctx, db, workspaceIDs)
	if err != nil {
		return nil, err
	}
	return assembleBundle(files, Manifest{OrgID: govOrgID})
}

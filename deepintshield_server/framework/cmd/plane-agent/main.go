// Command plane-agent is the data-plane side of the Phase-3 Enterprise-VPC
// tunnel. It runs as a lightweight sidecar inside the customer's VPC and:
//
//   - dials the control plane (app.deepintshield.com) over mTLS, pinning the
//     CP serving-cert SHA-256, presenting the client cert issued at onboarding
//   - an ORG cert (one DP per org, serves all the org's tenants/workspaces)
//     or a legacy per-tenant cert; the CP derives the scope from the cert CN;
//   - polls /api/tunnel/config for the latest signed config bundle and writes
//     it (plus its revision) to a seed directory the data plane reads;
//   - pushes aggregate usage counters (counts only, no payload) to
//     /api/tunnel/meter for billing.
//
// It is intentionally stdlib-only and poll-based: no customer content ever
// leaves the VPC, and a CP outage just means the last-known-good bundle stays
// in place. Configuration is via flags or the matching env vars.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	cpEndpoint  string
	clientCert  string
	clientKey   string
	pinnedSHA   string
	orgID       string // set for a one-DP-per-org deployment (scope is in the cert)
	version     string // this DP's running image version (reported to the CP)
	workspaceID string
	outDir      string
	metersFile  string
	interval    time.Duration
	once        bool
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	var c config
	flag.StringVar(&c.cpEndpoint, "cp-endpoint", envOr("CP_ENDPOINT", "https://app.deepintshield.com"), "control-plane base URL")
	flag.StringVar(&c.clientCert, "client-cert", envOr("CLIENT_CERT_FILE", "/etc/deepintshield/tunnel/tls.crt"), "PEM client certificate")
	flag.StringVar(&c.clientKey, "client-key", envOr("CLIENT_KEY_FILE", "/etc/deepintshield/tunnel/tls.key"), "PEM client private key")
	flag.StringVar(&c.pinnedSHA, "pinned-cp-sha256", envOr("PINNED_CP_CERT_SHA256", ""), "pinned CP serving-cert SHA-256 (hex)")
	flag.StringVar(&c.orgID, "org-id", envOr("ORG_ID", ""), "governance org id for a one-DP-per-org deployment (informational; the org cert carries the scope - leave workspace-id empty)")
	flag.StringVar(&c.version, "version", envOr("DP_VERSION", ""), "this data plane's running image version (reported to the CP for visibility; set to the image tag)")
	flag.StringVar(&c.workspaceID, "workspace-id", envOr("WORKSPACE_ID", ""), "workspace to sync for a legacy per-tenant DP (org DPs leave this empty)")
	flag.StringVar(&c.outDir, "out-dir", envOr("OUT_DIR", "/var/lib/deepintshield/config"), "directory to write the config bundle")
	flag.StringVar(&c.metersFile, "meters-file", envOr("METERS_FILE", ""), "optional JSON file of counters to push")
	interval := envOr("INTERVAL", "60s")
	flag.StringVar(&interval, "interval", interval, "poll interval (e.g. 60s)")
	flag.BoolVar(&c.once, "once", false, "run a single sync cycle and exit")
	flag.Parse()
	d, err := time.ParseDuration(interval)
	if err != nil || d <= 0 {
		d = 60 * time.Second
	}
	c.interval = d
	return c
}

func main() {
	c := loadConfig()
	log.SetFlags(log.LstdFlags | log.LUTC)

	certPEM, err := os.ReadFile(c.clientCert)
	if err != nil {
		log.Fatalf("plane-agent: read client cert: %v", err)
	}
	keyPEM, err := os.ReadFile(c.clientKey)
	if err != nil {
		log.Fatalf("plane-agent: read client key: %v", err)
	}
	client, err := newHTTPClient(certPEM, keyPEM, c.pinnedSHA)
	if err != nil {
		log.Fatalf("plane-agent: build http client: %v", err)
	}
	certHeader := base64.StdEncoding.EncodeToString(certPEM)

	if err := os.MkdirAll(c.outDir, 0o755); err != nil {
		log.Fatalf("plane-agent: mkdir out-dir: %v", err)
	}

	agent := &agent{cfg: c, http: client, certHeader: certHeader}
	log.Printf("plane-agent: started; cp=%s out=%s interval=%s", c.cpEndpoint, c.outDir, c.interval)
	for {
		if err := agent.syncConfig(); err != nil {
			log.Printf("plane-agent: config sync error: %v", err)
		}
		if c.metersFile != "" {
			if err := agent.pushMeters(); err != nil {
				log.Printf("plane-agent: meter push error: %v", err)
			}
		}
		if c.once {
			return
		}
		time.Sleep(c.interval)
	}
}

type agent struct {
	cfg        config
	http       *http.Client
	certHeader string
}

func (a *agent) revisionPath() string { return filepath.Join(a.cfg.outDir, ".revision") }

func (a *agent) lastRevision() string {
	b, err := os.ReadFile(a.revisionPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a *agent) syncConfig() error {
	url := strings.TrimRight(a.cfg.cpEndpoint, "/") + "/api/tunnel/config"
	q := "?since=" + a.lastRevision()
	if a.cfg.workspaceID != "" {
		q += "&workspace_id=" + a.cfg.workspaceID
	}
	req, err := http.NewRequest(http.MethodGet, url+q, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-DIS-Client-Cert", a.certHeader)
	if a.cfg.version != "" {
		req.Header.Set("X-DIS-DP-Version", a.cfg.version) // version heartbeat (visibility)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// The CP advertises the current recommended release; surface an upgrade hint
	// (we never auto-apply - the customer/GitOps controls image rollouts).
	a.checkRecommendedVersion(resp.Header.Get("X-DIS-Recommended-Version"))
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil // config unchanged - keep last-known-good
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		rev := resp.Header.Get("X-DIS-Config-Revision")
		bundlePath := filepath.Join(a.cfg.outDir, "config-bundle.tgz")
		if err := os.WriteFile(bundlePath, body, 0o600); err != nil {
			return err
		}
		if rev != "" {
			if err := os.WriteFile(a.revisionPath(), []byte(rev), 0o600); err != nil {
				return err
			}
		}
		log.Printf("plane-agent: applied config bundle (%d bytes, rev=%s) -> %s", len(body), rev, bundlePath)
		return nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("config sync: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
}

// checkRecommendedVersion logs an upgrade hint when the CP-advertised recommended
// release differs from this DP's running version. Notify only - image rollouts
// stay under the customer's control (helm upgrade / GitOps); the agent never
// self-applies.
func (a *agent) checkRecommendedVersion(recommended string) {
	recommended = strings.TrimSpace(recommended)
	if recommended == "" || a.cfg.version == "" || recommended == a.cfg.version {
		return
	}
	log.Printf("plane-agent: UPGRADE AVAILABLE - running %s, recommended %s. Bump the chart image tags (server/guard/models) to %s when you're ready.",
		a.cfg.version, recommended, recommended)
}

type meterCounters struct {
	GovernedRequests int64 `json:"governed_requests"`
	LoggedRequests   int64 `json:"logged_requests"`
	GuardrailEvals   int64 `json:"guardrail_evals"`
}

func (a *agent) pushMeters() error {
	raw, err := os.ReadFile(a.cfg.metersFile)
	if err != nil {
		return err
	}
	var counters meterCounters
	if err := json.Unmarshal(raw, &counters); err != nil {
		return fmt.Errorf("parse meters file: %w", err)
	}
	// Dedup window: hourly. A re-pushed window is a no-op on the CP.
	now := time.Now().UTC()
	dedup := now.Format("2006-01-02T15")
	payload := map[string]any{
		"dedup_key":         dedup,
		"occurred_at":       now.Format(time.RFC3339),
		"governed_requests": counters.GovernedRequests,
		"logged_requests":   counters.LoggedRequests,
		"guardrail_evals":   counters.GuardrailEvals,
	}
	body, _ := json.Marshal(payload)
	url := strings.TrimRight(a.cfg.cpEndpoint, "/") + "/api/tunnel/meter"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-DIS-Client-Cert", a.certHeader)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("meter push: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	log.Printf("plane-agent: pushed meters window=%s -> %s", dedup, strings.TrimSpace(string(respBody)))
	return nil
}

// newHTTPClient builds an mTLS client that presents the tunnel client cert and,
// when a pin is configured, requires the CP serving cert to match the pinned
// SHA-256 (defeating a compromised public CA). Over plain http (local dev) the
// TLS config is simply unused.
func newHTTPClient(certPEM, keyPEM []byte, pinnedSHA string) (*http.Client, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if pin := strings.ToLower(strings.TrimSpace(pinnedSHA)); pin != "" {
		// Pin the leaf serving cert. We still let the platform roots verify
		// the chain; the pin is an additional gate, not a replacement.
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("CP serving cert SHA-256 %s does not match pin %s", got, pin)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

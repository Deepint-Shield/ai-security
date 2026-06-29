package configbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestExportRedactsVKSecrets(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Minimal schema covering one safe table and the secret-bearing VK table.
	db.Exec(`CREATE TABLE guardrail_policies (id TEXT, name TEXT, workspace_id TEXT)`)
	db.Exec(`CREATE TABLE governance_virtual_keys (id TEXT, name TEXT, tenant_id TEXT, workspace_id TEXT, value TEXT, cache_key TEXT, created_at DATETIME, updated_at DATETIME)`)
	db.Exec(`INSERT INTO guardrail_policies VALUES ('gp-1','PII Guard','ws-1')`)
	db.Exec(`INSERT INTO governance_virtual_keys (id,name,tenant_id,workspace_id,value,cache_key) VALUES ('vk-1','prod-key','t-1','ws-1','SECRET-vk-value-do-not-leak','SECRET-cache')`)

	bundle, err := Export(context.Background(), db, "t-1", "ws-1")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bundle.Revision == "" {
		t.Fatal("expected a non-empty revision")
	}

	files := untar(t, bundle.Data)
	for _, want := range []string{"manifest.json", "guardrail_policies.json", "virtual_keys.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s; has %v", want, keys(files))
		}
	}

	// VK secrets must never appear anywhere in the bundle.
	for name, data := range files {
		if strings.Contains(string(data), "SECRET-vk-value-do-not-leak") || strings.Contains(string(data), "SECRET-cache") {
			t.Fatalf("VK secret leaked into %s", name)
		}
	}
	// …but the VK reference (id/name) is present.
	if !strings.Contains(string(files["virtual_keys.json"]), "prod-key") {
		t.Fatal("expected VK reference (name) in virtual_keys.json")
	}

	// Sanity: the manifest records the workspace + a bundle hash.
	var m Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.WorkspaceID != "ws-1" || m.BundleSHA256 == "" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func untar(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[hdr.Name] = b
	}
	return out
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

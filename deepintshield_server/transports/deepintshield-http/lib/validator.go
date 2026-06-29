// Package lib provides core functionality for the DeepIntShield HTTP service.
// This file contains JSON schema validation for config files.
package lib

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// embeddedConfigSchema is the config JSON schema bundled into the binary so
// config validation never depends on a network fetch. Kept in sync with
// transports/config.schema.json.
//
//go:embed config.schema.json
var embeddedConfigSchema []byte

// localSchemaCandidates lists paths (relative to CWD) where config.schema.json may be found
// when running from a source checkout. Checked in order before falling back to the remote URL.
var localSchemaCandidates = []string{
	"/app/config.schema.json",       // bundled server image
	"config.schema.json",            // running from transports/
	"../config.schema.json",         // running from transports/deepintshield-http/
	"transports/config.schema.json", // running from repo root
}

func schemaCandidatePaths(executablePath string) []string {
	candidates := make([]string, 0, len(localSchemaCandidates)+2)
	seen := make(map[string]struct{}, len(localSchemaCandidates)+2)

	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}

	if executablePath != "" {
		execDir := filepath.Dir(executablePath)
		add(filepath.Join(execDir, "config.schema.json"))
		add(filepath.Join(execDir, "..", "config.schema.json"))
	}

	for _, candidate := range localSchemaCandidates {
		add(candidate)
	}

	return candidates
}

// tryLoadLocalSchema attempts to read config.schema.json from known local paths.
// Returns nil if none are found.
func tryLoadLocalSchema() []byte {
	executablePath, _ := os.Executable()
	for _, p := range schemaCandidatePaths(executablePath) {
		data, err := os.ReadFile(p)
		if err == nil {
			return data
		}
	}
	return nil
}

// ValidateConfigSchema validates config data against the JSON schema.
// Returns nil if valid, or a formatted error describing all validation failures.
// An optional schemaOverride can be provided to use a local schema instead of fetching from the remote URL.
func ValidateConfigSchema(data []byte, schemaOverride ...[]byte) error {
	var configSchemaJSONBytes []byte
	if len(schemaOverride) > 0 && len(schemaOverride[0]) > 0 {
		configSchemaJSONBytes = schemaOverride[0]
	} else if localSchema := tryLoadLocalSchema(); localSchema != nil {
		// Prefer the local schema file from the source checkout when available.
		// This avoids validating against a potentially stale remote schema.
		configSchemaJSONBytes = localSchema
	} else if len(embeddedConfigSchema) > 0 {
		// Use the schema bundled into the binary - no network needed.
		configSchemaJSONBytes = embeddedConfigSchema
	} else {
		// Last-resort remote fetch. Bounded by a timeout and fail-open so it can
		// never hang the gateway (or tests) if the host is unreachable.
		client := &http.Client{Timeout: 10 * time.Second}
		configSchemaJSON, err := client.Get("https://deepintshield.com/schema")
		if err != nil {
			logger.Warn("failed to fetch config schema: %v. running without config.json schema validation", err)
			return nil
		}
		defer configSchemaJSON.Body.Close()
		var readErr error
		configSchemaJSONBytes, readErr = io.ReadAll(configSchemaJSON.Body)
		if readErr != nil {
			logger.Warn("failed to download config schema: %v. running without config.json schema validation", readErr)
			return nil
		}
	}
	// Parse the schema JSON
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(configSchemaJSONBytes))
	if err != nil {
		return fmt.Errorf("failed to parse config schema JSON: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("config.schema.json", schemaDoc); err != nil {
		return fmt.Errorf("failed to add config schema resource: %w", err)
	}
	// Compile the schema
	compiledSchema, err := c.Compile("config.schema.json")
	if err != nil {
		return fmt.Errorf("failed to compile config schema: %w", err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	err = compiledSchema.Validate(v)
	if err == nil {
		return nil
	}
	// Format validation errors for better readability
	return formatValidationError(err)
}

// formatValidationError converts jsonschema validation errors into user-friendly messages
func formatValidationError(err error) error {
	validationErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return err
	}

	// Use the GoString format which provides detailed hierarchical output
	return fmt.Errorf("schema validation failed:\n%s", validationErr.GoString())
}

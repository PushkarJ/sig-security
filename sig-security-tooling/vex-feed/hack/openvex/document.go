// Package openvex holds the OpenVEX document/statement types shared by the
// vex-feed hack tools, plus helpers to load and save them.
package openvex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// ContextV02 is the OpenVEX v0.2.0 JSON-LD context every document in this
// repo declares.
const ContextV02 = "https://openvex.dev/ns/v0.2.0"

// Document is a single OpenVEX document: either a per-issue source file
// under files/, or the combined feed.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one VEX determination for one vulnerability/product pair.
type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Products      []Product     `json:"products"`
	Status        string        `json:"status"`
	// Justification is a pointer because its presence/absence (not just
	// emptiness) is meaningful: build-feed's conflict detection treats a
	// group mixing a nil justification with a non-nil one as a conflict.
	Justification   *string `json:"justification,omitempty"`
	StatusNotes     string  `json:"status_notes,omitempty"`
	ActionStatement string  `json:"action_statement,omitempty"`
}

// Vulnerability identifies the CVE a Statement is about.
type Vulnerability struct {
	Name string `json:"name"`
}

// Product is the VEX subject a Statement's status applies to.
type Product struct {
	ID            string         `json:"@id"`
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponent is a PURL-identified part of a Product.
type Subcomponent struct {
	ID string `json:"@id"`
}

// Load reads and parses a single OpenVEX document from path.
func Load(path string) (Document, error) {
	// #nosec G304 -- callers only ever pass a fixed repo-relative constant
	// or a glob result derived from a fixed pattern, never raw external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var doc Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return Document{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return doc, nil
}

// Save writes doc to path as 2-space-indented JSON with a single trailing
// newline, matching Python's `json.dump(doc, f, indent=2); f.write("\n")`.
func Save(path string, doc Document) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // Python's json.dump never HTML-escapes < > &
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("failed to marshal document for %s: %w", path, err)
	}
	// #nosec G304 -- same rationale as Load: fixed/glob-derived paths only.
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

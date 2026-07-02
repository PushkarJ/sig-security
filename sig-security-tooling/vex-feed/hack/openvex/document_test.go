package openvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveOmitsAbsentOptionalFields(t *testing.T) {
	doc := Document{
		Context: ContextV02,
		ID:      "https://github.com/kubernetes/kubernetes/issues/1",
		Author:  "kubernetes maintainers",
		Version: 1,
		Statements: []Statement{
			{
				Vulnerability: Vulnerability{Name: "CVE-2000-0001"},
				Products:      []Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
				Status:        "under_investigation",
			},
		},
	}
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := Save(path, doc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- fixed test tempdir path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(b)
	for _, absent := range []string{"justification", "status_notes", "action_statement", "subcomponents"} {
		if strings.Contains(s, absent) {
			t.Errorf("expected %q to be omitted, got:\n%s", absent, s)
		}
	}
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("expected output to end with a single trailing newline, got: %q", s)
	}
}

func TestSaveIncludesOptionalFieldsInOrder(t *testing.T) {
	justification := "vulnerable_code_not_present"
	doc := Document{
		Context: ContextV02,
		ID:      "https://github.com/kubernetes/kubernetes/issues/1",
		Author:  "kubernetes maintainers",
		Version: 1,
		Statements: []Statement{
			{
				Vulnerability: Vulnerability{Name: "CVE-2000-0001"},
				Products: []Product{{
					ID:            "pkg:golang/k8s.io/kubernetes",
					Subcomponents: []Subcomponent{{ID: "pkg:golang/stdlib"}},
				}},
				Status:          "not_affected",
				Justification:   &justification,
				StatusNotes:     "some notes",
				ActionStatement: "some action",
			},
		},
	}
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := Save(path, doc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- fixed test tempdir path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(b)

	keys := []string{
		`"@context"`, `"@id"`, `"author"`, `"timestamp"`, `"version"`, `"statements"`,
		`"vulnerability"`, `"products"`, `"status"`, `"justification"`, `"status_notes"`, `"action_statement"`,
	}
	lastIdx := -1
	for _, k := range keys {
		idx := strings.Index(s, k)
		if idx < 0 {
			t.Fatalf("expected key %s in output:\n%s", k, s)
		}
		if idx < lastIdx {
			t.Errorf("key %s appears out of order in output:\n%s", k, s)
		}
		lastIdx = idx
	}
}

func TestLoadSaveRoundTripRealFixture(t *testing.T) {
	// files/issue-138329.openvex.json has both justification and
	// status_notes populated -- a good real-world round-trip fixture.
	const src = "../../files/issue-138329.openvex.json"
	original, err := os.ReadFile(src) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", src, err)
	}

	doc, err := Load(src)
	if err != nil {
		t.Fatalf("Load(%s): %v", src, err)
	}

	dst := filepath.Join(t.TempDir(), "roundtrip.json")
	if err := Save(dst, doc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := os.ReadFile(dst) // #nosec G304 -- fixed test tempdir path
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", dst, err)
	}

	if string(got) != string(original) {
		t.Errorf("round trip did not reproduce the original bytes.\n--- original ---\n%s\n--- got ---\n%s", original, got)
	}
}

func TestLoadParsesJustificationNilWhenAbsent(t *testing.T) {
	const src = "../../files/issue-140092.openvex.json" // no justification in this fixture
	doc, err := Load(src)
	if err != nil {
		t.Fatalf("Load(%s): %v", src, err)
	}
	if len(doc.Statements) == 0 {
		t.Fatalf("expected at least one statement in %s", src)
	}
	if doc.Statements[0].Justification != nil {
		t.Errorf("expected nil Justification, got %q", *doc.Statements[0].Justification)
	}
}

func TestDocumentUnmarshalRoundTripIsStable(t *testing.T) {
	const src = "../../files/issue-139221.openvex.json" // has justification populated
	doc, err := Load(src)
	if err != nil {
		t.Fatalf("Load(%s): %v", src, err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc2 Document
	if err := json.Unmarshal(b, &doc2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if doc2.Statements[0].Justification == nil || *doc2.Statements[0].Justification != *doc.Statements[0].Justification {
		t.Errorf("justification did not survive marshal/unmarshal round trip")
	}
}

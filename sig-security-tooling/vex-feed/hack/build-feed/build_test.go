package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func TestIssueNum(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      int
		wantError bool
	}{
		{name: "typical", path: "files/issue-140092.openvex.json", want: 140092},
		{name: "small number", path: "issue-1.openvex.json", want: 1},
		{name: "no match", path: "files/not-an-issue.json", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := issueNum(tt.path)
			if tt.wantError {
				if err == nil {
					t.Fatalf("issueNum(%s) = %d, nil; want error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("issueNum(%s): %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("issueNum(%s) = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueStrings = %v, want %v", got, want)
	}
}

func TestUniqueInts(t *testing.T) {
	got := uniqueInts([]int{3, 1, 3, 2, 1})
	want := []int{1, 2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueInts = %v, want %v", got, want)
	}
}

func TestUniqueJustificationDisplays(t *testing.T) {
	v := "vulnerable_code_not_present"
	got := uniqueJustificationDisplays([]*string{nil, &v, nil})
	want := []string{"None", "vulnerable_code_not_present"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueJustificationDisplays = %v, want %v", got, want)
	}
}

func TestPyStrList(t *testing.T) {
	got := pyStrList([]string{"a", "b"})
	want := "['a', 'b']"
	if got != want {
		t.Errorf("pyStrList = %q, want %q", got, want)
	}
}

func TestPyIntList(t *testing.T) {
	got := pyIntList([]int{1, 2})
	want := "[1, 2]"
	if got != want {
		t.Errorf("pyIntList = %q, want %q", got, want)
	}
}

func TestLoadOverridesSkipsCommentKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "merge-overrides.json")
	content := `{
		"_comment": "this is a bare string, not an override object",
		"CVE-2000-0001": {"status_notes": "notes for 0001"},
		"CVE-2000-0002": {"action_statement": "do this"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadOverrides(path)
	if err != nil {
		t.Fatalf("loadOverrides: %v", err)
	}
	if _, ok := got["_comment"]; ok {
		t.Errorf("expected _comment key to be skipped")
	}
	if got["CVE-2000-0001"].StatusNotes != "notes for 0001" {
		t.Errorf("CVE-2000-0001 status_notes = %q", got["CVE-2000-0001"].StatusNotes)
	}
	if got["CVE-2000-0002"].ActionStatement != "do this" {
		t.Errorf("CVE-2000-0002 action_statement = %q", got["CVE-2000-0002"].ActionStatement)
	}
}

func writeFixture(t *testing.T, dir, name string, doc openvex.Document) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := openvex.Save(path, doc); err != nil {
		t.Fatalf("Save(%s): %v", path, err)
	}
	return path
}

func strPtr(s string) *string { return &s }

func TestBuildStatements_SingleSourcePassThrough(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
			StatusNotes:   "fixed upstream",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	if len(result.statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.statements))
	}
	got := result.statements[0]
	if got.Status != "fixed" || got.StatusNotes != "fixed upstream" {
		t.Errorf("unexpected statement: %+v", got)
	}
}

func TestBuildStatements_MultiSourceWithOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
			StatusNotes:   "from issue 100",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
			StatusNotes:   "from issue 200",
		}},
	})

	overrides := map[string]override{
		"CVE-2000-0001": {StatusNotes: "merged notes"},
	}
	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), overrides)
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	if len(result.statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.statements))
	}
	if result.statements[0].StatusNotes != "merged notes" {
		t.Errorf("expected override notes, got %q", result.statements[0].StatusNotes)
	}
}

func TestBuildStatements_MultiSourceWithoutOverrideConflicts(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
	if len(result.statements) != 0 {
		t.Fatalf("expected 0 statements when conflict occurs, got %d", len(result.statements))
	}
}

func TestBuildStatements_ConflictingStatus(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "not_affected",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "would be ignored anyway"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
}

func TestBuildStatements_ConflictingJustificationIncludingNilVsValue(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "not_affected",
			Justification: strPtr("vulnerable_code_not_present"),
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{ID: "pkg:golang/k8s.io/kubernetes"}},
			Status:        "not_affected",
			// no justification here -- nil vs a real value is a conflict
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "would be ignored anyway"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
}

func TestBuildStatements_SubcomponentUnionAndCollapse(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products: []openvex.Product{{
				ID:            "pkg:golang/k8s.io/kubernetes",
				Subcomponents: []openvex.Subcomponent{{ID: "pkg:golang/stdlib@v1.25.6"}},
			}},
			Status: "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products: []openvex.Product{{
				ID:            "pkg:golang/k8s.io/kubernetes",
				Subcomponents: []openvex.Subcomponent{{ID: "pkg:golang/stdlib"}},
			}},
			Status: "fixed",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "merged"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	subs := result.statements[0].Products[0].Subcomponents
	if len(subs) != 1 || subs[0].ID != "pkg:golang/stdlib" {
		t.Errorf("expected collapsed subcomponent pkg:golang/stdlib, got %v", subs)
	}
}

func TestBuildStatements_NoFilesFound(t *testing.T) {
	dir := t.TempDir()
	_, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err == nil {
		t.Fatal("expected an error when no per-issue files are found")
	}
}

// TestBuildStatements_RealCorpus is the load-bearing regression test: it
// proves the Go port reproduces exactly what build-feed.py already produced
// for the real, committed data.
func TestBuildStatements_RealCorpus(t *testing.T) {
	overrides, err := loadOverrides("../merge-overrides.json")
	if err != nil {
		t.Fatalf("loadOverrides: %v", err)
	}
	result, err := buildStatements("../../files/issue-*.openvex.json", overrides)
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts against real corpus: %v", result.conflicts)
	}

	want, err := openvex.Load("../../kubernetes-vex-feed-draft.openvex.json")
	if err != nil {
		t.Fatalf("Load real feed: %v", err)
	}

	if !reflect.DeepEqual(result.statements, want.Statements) {
		t.Errorf("built statements do not match the committed feed.\ngot:  %+v\nwant: %+v", result.statements, want.Statements)
	}
}

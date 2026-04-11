package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/drift"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/skillbom"
)

// writeSkillBOM writes a SkillBOM to a temp file and returns the path.
func writeSkillBOM(t *testing.T, dir string, name string, bom *skillbom.SkillBOM) string {
	t.Helper()
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshaling SkillBOM: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing SkillBOM: %v", err)
	}
	return path
}

func TestRunDrift_IdenticalBOMs(t *testing.T) {
	dir := t.TempDir()

	bom := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", bom)
	newPath := writeSkillBOM(t, dir, "new.json", bom)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No drift signals detected") {
		t.Errorf("expected 'No drift signals detected' in output, got:\n%s", output)
	}
}

func TestRunDrift_CapabilityEscalation(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.1",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read", "network.egress"},
		ContentHash:  "sha256:bbb222",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "network.egress") {
		t.Errorf("expected 'network.egress' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "CRIT") {
		t.Errorf("expected 'CRIT' severity marker in output, got:\n%s", output)
	}
	if !strings.Contains(output, "WARNING") {
		t.Errorf("expected WARNING message in output, got:\n%s", output)
	}
}

func TestRunDrift_StrictMode_Fails(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.1",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read", "network.egress"},
		ContentHash:  "sha256:bbb222",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--strict", oldPath, newPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected non-zero exit for strict mode with critical signals")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Errorf("error should mention 'critical', got: %v", err)
	}
}

func TestRunDrift_StrictMode_Passes(t *testing.T) {
	dir := t.TempDir()

	bom := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", bom)
	newPath := writeSkillBOM(t, dir, "new.json", bom)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--strict", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("strict mode should pass for identical BOMs: %v", err)
	}
}

func TestRunDrift_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.1.0",
		Description:  "Reviews code and provides suggestions",
		Capabilities: []string{"filesystem.read", "git.diff"},
		ContentHash:  "sha256:bbb222",
		Components:   5,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--json", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid JSON with the report wrapper.
	var output driftJSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}

	if output.Report == nil {
		t.Fatal("expected report in JSON output")
	}
	if len(output.Report.Signals) == 0 {
		t.Error("expected at least one signal in JSON output")
	}
	if output.Report.DriftResult == nil {
		t.Error("expected driftResult in JSON output")
	}
	// Without --enforce, no enforcement section.
	if output.Enforcement != nil {
		t.Error("expected no enforcement section without --enforce flag")
	}
}

func TestRunDrift_MissingFile(t *testing.T) {
	dir := t.TempDir()

	bom := &skillbom.SkillBOM{
		Format:      skillbom.Format,
		SkillName:   "test",
		ContentHash: "sha256:aaa",
	}
	oldPath := writeSkillBOM(t, dir, "old.json", bom)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", oldPath, "/nonexistent/path.json"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRunDrift_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	bom := &skillbom.SkillBOM{
		Format:      skillbom.Format,
		SkillName:   "test",
		ContentHash: "sha256:aaa",
	}
	oldPath := writeSkillBOM(t, dir, "old.json", bom)

	invalidPath := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", oldPath, invalidPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRunDrift_RequiresExactlyTwoArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{"drift"}},
		{"one arg", []string{"drift", "old.json"}},
		{"three args", []string{"drift", "a.json", "b.json", "c.json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd("test", "abc", "now")
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Error("expected error for wrong number of args")
			}
		})
	}
}

func TestLoadSkillBOM(t *testing.T) {
	dir := t.TempDir()

	expected := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "test-skill",
		Version:      "2.0.0",
		Description:  "A test skill",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:abc123",
		Components:   3,
	}

	path := writeSkillBOM(t, dir, "test.json", expected)

	loaded, err := loadSkillBOM(path)
	if err != nil {
		t.Fatalf("loadSkillBOM() error: %v", err)
	}

	if loaded.SkillName != expected.SkillName {
		t.Errorf("SkillName = %q, want %q", loaded.SkillName, expected.SkillName)
	}
	if loaded.Version != expected.Version {
		t.Errorf("Version = %q, want %q", loaded.Version, expected.Version)
	}
	if loaded.ContentHash != expected.ContentHash {
		t.Errorf("ContentHash = %q, want %q", loaded.ContentHash, expected.ContentHash)
	}
}

func TestSeverityMarker(t *testing.T) {
	tests := []struct {
		sev  drift.Severity
		want string
	}{
		{drift.SeverityCritical, "CRIT"},
		{drift.SeverityHigh, "HIGH"},
		{drift.SeverityMedium, " MED"},
		{drift.SeverityLow, " LOW"},
		{drift.Severity("unknown"), "  ? "},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := severityMarker(tt.sev); got != tt.want {
				t.Errorf("severityMarker(%q) = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}

func TestRunDrift_Enforce_Blocked(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.1",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read", "network.egress"},
		ContentHash:  "sha256:bbb222",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--enforce", oldPath, newPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for blocked enforcement")
	}
	if !strings.Contains(err.Error(), "BLOCKED") {
		t.Errorf("error should mention BLOCKED, got: %v", err)
	}

	// Verify exit code via driftExitError.
	var exitErr *driftExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() != 1 {
			t.Errorf("expected exit code 1 for blocked, got %d", exitErr.ExitCode())
		}
	}
}

func TestRunDrift_Enforce_RequiresApproval(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code changes and provides feedback on style, bugs, and best practices",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	// Non-dangerous capability addition -> high severity -> require-approval.
	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.1.0",
		Description:  "Reviews code changes and provides feedback on style, bugs, and best practices",
		Capabilities: []string{"filesystem.read", "git.blame"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--enforce", oldPath, newPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for require-approval enforcement")
	}
	if !strings.Contains(err.Error(), "APPROVAL REQUIRED") {
		t.Errorf("error should mention APPROVAL REQUIRED, got: %v", err)
	}

	var exitErr *driftExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2 for require-approval, got %d", exitErr.ExitCode())
		}
	}
}

func TestRunDrift_Enforce_Passes(t *testing.T) {
	dir := t.TempDir()

	bom := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", bom)
	newPath := writeSkillBOM(t, dir, "new.json", bom)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--enforce", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("enforce mode should pass for identical BOMs: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "PASS") {
		t.Errorf("expected PASS in enforcement output, got:\n%s", output)
	}
}

func TestRunDrift_Enforce_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.1.0",
		Description:  "Reviews code and provides suggestions",
		Capabilities: []string{"filesystem.read", "git.diff"},
		ContentHash:  "sha256:bbb222",
		Components:   5,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--json", "--enforce", oldPath, newPath})

	// This may return an error due to enforcement, that's OK.
	_ = cmd.Execute()

	// Verify output has enforcement section.
	var output driftJSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}

	if output.Report == nil {
		t.Fatal("expected report in JSON output")
	}
	if output.Enforcement == nil {
		t.Fatal("expected enforcement section in JSON output with --enforce flag")
	}
	if output.Enforcement.Decision == "" {
		t.Error("expected non-empty decision in enforcement output")
	}
	if output.Enforcement.Summary == "" {
		t.Error("expected non-empty summary in enforcement output")
	}
}

func TestRunDrift_Enforce_LowSeverityAutoApproves(t *testing.T) {
	dir := t.TempDir()

	oldBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	// Only a version change (low severity) -> auto-approve.
	newBOM := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.1",
		Description:  "Reviews code",
		Capabilities: []string{"filesystem.read"},
		ContentHash:  "sha256:aaa111",
		Components:   3,
	}

	oldPath := writeSkillBOM(t, dir, "old.json", oldBOM)
	newPath := writeSkillBOM(t, dir, "new.json", newBOM)

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"drift", "--enforce", oldPath, newPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("low severity should auto-approve, got error: %v", err)
	}
}

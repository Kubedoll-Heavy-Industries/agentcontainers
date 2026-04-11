package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPolicyCmd_HasSubcommands(t *testing.T) {
	cmd := newPolicyCmd()
	subs := cmd.Commands()
	names := make(map[string]bool)
	for _, c := range subs {
		names[c.Name()] = true
	}
	for _, want := range []string{"validate", "diff"} {
		if !names[want] {
			t.Errorf("missing subcommand %q", want)
		}
	}
	for _, removed := range []string{"pull", "push"} {
		if names[removed] {
			t.Errorf("subcommand %q should have been removed", removed)
		}
	}
}

func TestPolicyValidate_ValidFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"requireSignatures": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newPolicyCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"validate", policyPath})
	if err := cmd.Execute(); err != nil {
		t.Errorf("validate valid policy: %v", err)
	}
	if !strings.Contains(buf.String(), "valid") {
		t.Errorf("output = %q, want it to mention 'valid'", buf.String())
	}
}

func TestPolicyValidate_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	// minSLSALevel must be 0-4; 5 is invalid.
	if err := os.WriteFile(policyPath, []byte(`{"minSLSALevel": 5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newPolicyCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"validate", policyPath})
	if err := cmd.Execute(); err == nil {
		t.Error("validate invalid policy: expected error, got nil")
	}
}

func TestPolicyValidate_MissingFile(t *testing.T) {
	cmd := newPolicyCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetArgs([]string{"validate", "/nonexistent/policy.json"})
	if err := cmd.Execute(); err == nil {
		t.Error("validate missing file: expected error, got nil")
	}
}

func TestPolicyValidate_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(policyPath, []byte(`not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newPolicyCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetArgs([]string{"validate", policyPath})
	if err := cmd.Execute(); err == nil {
		t.Error("validate invalid JSON: expected error, got nil")
	}
}

func TestPolicyValidate_MaxAgeRejected(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"maxAge": "7d"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newPolicyCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"validate", policyPath})
	// maxAge is explicitly rejected since PRD-017 removed it.
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for maxAge field, got nil")
	}
	if !strings.Contains(err.Error(), "maxAge") {
		t.Errorf("expected error mentioning 'maxAge', got: %v", err)
	}
}

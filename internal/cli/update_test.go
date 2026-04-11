package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateCmd_DefaultFlags(t *testing.T) {
	cmd := newUpdateCmd()

	dryRun, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		t.Fatalf("getting dry-run flag: %v", err)
	}
	if dryRun {
		t.Error("dry-run should default to false")
	}

	configFlag, err := cmd.Flags().GetString("config")
	if err != nil {
		t.Fatalf("getting config flag: %v", err)
	}
	if configFlag != "" {
		t.Errorf("config should default to empty, got %q", configFlag)
	}
}

func TestUpdateCmd_NoDevcontainer(t *testing.T) {
	dir := t.TempDir()

	// Create agentcontainer.json but no devcontainer.json.
	acPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(acPath, []byte(`{"name":"test","image":"alpine:3.19"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--config", acPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no devcontainer.json exists")
	}
	if !strings.Contains(err.Error(), "no devcontainer.json found") {
		t.Errorf("expected 'no devcontainer.json found' in error, got: %v", err)
	}
}

func TestUpdateCmd_NoChanges(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"alpine:3.19"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No changes detected") {
		t.Errorf("expected 'No changes detected', got: %s", buf.String())
	}
}

func TestUpdateCmd_DryRun(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"node:20-slim"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--dry-run", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "image:") {
		t.Errorf("expected diff output with 'image:', got: %s", output)
	}
	if !strings.Contains(output, "alpine:3.19") {
		t.Errorf("expected old value in diff, got: %s", output)
	}
	if !strings.Contains(output, "node:20-slim") {
		t.Errorf("expected new value in diff, got: %s", output)
	}

	// File should NOT be modified.
	data, _ := os.ReadFile(acPath)
	if string(data) != acContent {
		t.Error("dry-run should not modify the file")
	}
}

func TestUpdateCmd_ApplyChanges(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"node:20-slim"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Pipe "y" to stdin for confirmation.
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"update", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Updated") {
		t.Errorf("expected 'Updated' message, got: %s", output)
	}

	// Verify the file was updated.
	data, err := os.ReadFile(acPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "node:20-slim") {
		t.Errorf("expected updated image in file, got: %s", string(data))
	}
}

func TestUpdateCmd_UserDeclinesChange(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"node:20-slim"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Pipe "n" to stdin to decline.
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"update", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Update cancelled") {
		t.Errorf("expected 'Update cancelled' message, got: %s", output)
	}

	// File should NOT be modified.
	data, _ := os.ReadFile(acPath)
	if string(data) != acContent {
		t.Error("file should not be modified when user declines")
	}
}

func TestUpdateCmd_PreservesAgentKey(t *testing.T) {
	dir := t.TempDir()

	acContent := `{
  "name": "test",
  "image": "alpine:3.19",
  "agent": {
    "capabilities": {
      "network": {
        "deny": ["*"]
      }
    }
  }
}`
	dcContent := `{"name":"test","image":"node:20-slim"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"update", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(acPath)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)

	// Image should be updated.
	if !strings.Contains(content, "node:20-slim") {
		t.Errorf("expected updated image, got: %s", content)
	}

	// Agent key should be preserved.
	if !strings.Contains(content, `"agent"`) {
		t.Errorf("agent key should be preserved, got: %s", content)
	}
	if !strings.Contains(content, `"deny"`) {
		t.Errorf("agent deny rules should be preserved, got: %s", content)
	}
}

func TestUpdateCmd_AddedField(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"alpine:3.19","remoteUser":"node"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--dry-run", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "remoteUser") {
		t.Errorf("expected remoteUser in diff, got: %s", output)
	}
	if !strings.Contains(output, "(none)") {
		t.Errorf("expected '(none)' for added field, got: %s", output)
	}
}

func TestUpdateCmd_RemovedField(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"test","image":"alpine:3.19","remoteUser":"node"}`
	dcContent := `{"name":"test","image":"alpine:3.19"}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--dry-run", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "remoteUser") {
		t.Errorf("expected remoteUser in diff, got: %s", output)
	}
	if !strings.Contains(output, "(removed)") {
		t.Errorf("expected '(removed)' for removed field, got: %s", output)
	}
}

func TestUpdateCmd_DevcontainerInSubdir(t *testing.T) {
	dir := t.TempDir()

	// agentcontainer.json at root, devcontainer.json in .devcontainer/
	acPath := filepath.Join(dir, "agentcontainer.json")
	dcDir := filepath.Join(dir, ".devcontainer")
	if err := os.Mkdir(dcDir, 0755); err != nil {
		t.Fatal(err)
	}

	acContent := `{"name":"test","image":"alpine:3.19"}`
	dcContent := `{"name":"test","image":"node:20-slim"}`

	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dcDir, "devcontainer.json"), []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--dry-run", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "image:") {
		t.Errorf("expected diff output, got: %s", output)
	}
}

func TestUpdateCmd_InvalidAgentcontainer(t *testing.T) {
	dir := t.TempDir()

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")

	if err := os.WriteFile(acPath, []byte("{not valid json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--config", acPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing agentcontainer.json") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestUpdateCmd_MultipleFieldChanges(t *testing.T) {
	dir := t.TempDir()

	acContent := `{"name":"old","image":"alpine:3.19"}`
	dcContent := `{"name":"new","image":"node:20","features":{"ghcr.io/devcontainers/features/go:1":{}}}`

	acPath := filepath.Join(dir, "agentcontainer.json")
	dcPath := filepath.Join(dir, "devcontainer.json")
	if err := os.WriteFile(acPath, []byte(acContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dcPath, []byte(dcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"update", "--dry-run", "--config", acPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// Should show name change.
	if !strings.Contains(output, "name:") {
		t.Errorf("expected name change in output, got: %s", output)
	}
	// Should show image change.
	if !strings.Contains(output, "image:") {
		t.Errorf("expected image change in output, got: %s", output)
	}
	// Should show features addition.
	if !strings.Contains(output, "features:") {
		t.Errorf("expected features addition in output, got: %s", output)
	}
}

func TestComputeChanges(t *testing.T) {
	tests := []struct {
		name     string
		acJSON   string
		dcJSON   string
		expected int
	}{
		{
			name:     "no changes",
			acJSON:   `{"name":"test","image":"alpine"}`,
			dcJSON:   `{"name":"test","image":"alpine"}`,
			expected: 0,
		},
		{
			name:     "image changed",
			acJSON:   `{"image":"alpine"}`,
			dcJSON:   `{"image":"node"}`,
			expected: 1,
		},
		{
			name:     "field added in devcontainer",
			acJSON:   `{"image":"alpine"}`,
			dcJSON:   `{"image":"alpine","remoteUser":"root"}`,
			expected: 1,
		},
		{
			name:     "field removed from devcontainer",
			acJSON:   `{"image":"alpine","remoteUser":"root"}`,
			dcJSON:   `{"image":"alpine"}`,
			expected: 1,
		},
		{
			name:     "agent key ignored",
			acJSON:   `{"image":"alpine","agent":{"capabilities":{}}}`,
			dcJSON:   `{"image":"alpine"}`,
			expected: 0,
		},
		{
			name:     "non-devcontainer field ignored",
			acJSON:   `{"image":"alpine"}`,
			dcJSON:   `{"image":"alpine","customField":"value"}`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var acMap, dcMap map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tt.acJSON), &acMap); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.dcJSON), &dcMap); err != nil {
				t.Fatal(err)
			}

			changes := computeChanges(acMap, dcMap)
			if len(changes) != tt.expected {
				t.Errorf("expected %d changes, got %d: %v", tt.expected, len(changes), changes)
			}
		})
	}
}

func TestSummarizeJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"string", `"hello"`, "hello"},
		{"number", `42`, "42"},
		{"bool", `true`, "true"},
		{"short object", `{"a":"b"}`, `{"a":"b"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeJSON(json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("summarizeJSON(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestJSONEqual(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"identical", `"hello"`, `"hello"`, true},
		{"different", `"hello"`, `"world"`, false},
		{"whitespace", `{"a": 1}`, `{"a":1}`, true},
		{"key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"arrays same", `[1,2,3]`, `[1,2,3]`, true},
		{"arrays different", `[1,2,3]`, `[3,2,1]`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonEqual(json.RawMessage(tt.a), json.RawMessage(tt.b))
			if got != tt.want {
				t.Errorf("jsonEqual(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

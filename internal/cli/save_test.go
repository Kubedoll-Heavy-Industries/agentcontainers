package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveFromFile(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	capsContent := `{
  "shell": {"commands": [{"binary": "git"}, {"binary": "npm"}]},
  "network": {"egress": [{"host": "registry.npmjs.org", "port": 443}]}
}`
	capsPath := filepath.Join(dir, "caps.json")
	if err := os.WriteFile(capsPath, []byte(capsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"save", "--config", configPath, capsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("save command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Saved capabilities") {
		t.Errorf("expected 'Saved capabilities' in output, got:\n%s", output)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "npm") {
		t.Errorf("expected 'npm' in saved config, got:\n%s", content)
	}
	if !strings.Contains(content, "registry.npmjs.org") {
		t.Errorf("expected 'registry.npmjs.org' in saved config, got:\n%s", content)
	}
}

func TestSaveFromStdin(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	capsJSON := `{"shell": {"commands": [{"binary": "cargo"}]}}`

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetIn(strings.NewReader(capsJSON))
	cmd.SetArgs([]string{"save", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("save from stdin failed: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cargo") {
		t.Errorf("expected 'cargo' in saved config, got:\n%s", string(data))
	}
}

func TestSaveDryRun(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	capsJSON := `{"shell": {"commands": [{"binary": "npm"}]}}`
	capsPath := filepath.Join(dir, "caps.json")
	if err := os.WriteFile(capsPath, []byte(capsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"save", "--dry-run", "--config", configPath, capsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("save --dry-run failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "dry run") {
		t.Errorf("expected 'dry run' in output, got:\n%s", output)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "npm") {
		t.Error("file should not have been modified in dry-run mode")
	}
}

func TestSaveNoChanges(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	capsJSON := `{"shell": {"commands": [{"binary": "git"}]}}`

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetIn(strings.NewReader(capsJSON))
	cmd.SetArgs([]string{"save", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("save with no changes failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "No capability changes") {
		t.Errorf("expected 'No capability changes' in output, got:\n%s", output)
	}
}

func TestSaveInvalidCapsJSON(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetIn(strings.NewReader("{invalid json"))
	cmd.SetArgs([]string{"save", "--config", configPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid caps JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing capabilities JSON") {
		t.Errorf("error = %v, want error containing %q", err, "parsing capabilities JSON")
	}
}

func TestSaveEmptyStdin(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"save", "--config", configPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for empty stdin, got nil")
	}
	if !strings.Contains(err.Error(), "no capabilities provided") {
		t.Errorf("error = %v, want error containing %q", err, "no capabilities provided")
	}
}

func TestSavePreservesComments(t *testing.T) {
	dir := t.TempDir()

	configContent := `// Top comment
{
  // Name of the container
  "name": "test",
  "image": "alpine:3", // image comment
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	capsJSON := `{"shell": {"commands": [{"binary": "npm"}]}}`
	capsPath := filepath.Join(dir, "caps.json")
	if err := os.WriteFile(capsPath, []byte(capsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"save", "--config", configPath, capsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "Top comment") {
		t.Error("top comment was not preserved")
	}
	if !strings.Contains(content, "Name of the container") {
		t.Error("name comment was not preserved")
	}
	if !strings.Contains(content, "image comment") {
		t.Error("image comment was not preserved")
	}
	if !strings.Contains(content, "npm") {
		t.Error("new capability was not written")
	}
}

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInitNoDevcontainer verifies that running init in an empty directory
// produces a minimal agentcontainer.json with the default image and name.
func TestInitNoDevcontainer(t *testing.T) {
	dir := t.TempDir()

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	outPath := filepath.Join(dir, "agentcontainer.json")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected agentcontainer.json to be created: %v", err)
	}

	content := string(data)

	// Should contain the default image.
	if !strings.Contains(content, defaultImage) {
		t.Errorf("expected default image %q in output, got:\n%s", defaultImage, content)
	}

	// Should contain the default name.
	if !strings.Contains(content, defaultName) {
		t.Errorf("expected default name %q in output, got:\n%s", defaultName, content)
	}

	// Should contain default-deny agent capabilities.
	if !strings.Contains(content, `"agent"`) {
		t.Error("expected agent key in output")
	}
	if !strings.Contains(content, `"deny":  ["**/.env", "**/.env.*"]`) {
		t.Error("expected .env deny rule in output")
	}
	if !strings.Contains(content, `"deny":   ["*"]`) {
		t.Error("expected network deny-all rule in output")
	}
}

// TestInitWithDevcontainer verifies that when a devcontainer.json exists the
// generated agentcontainer.json inherits the image and name.
func TestInitWithDevcontainer(t *testing.T) {
	dir := t.TempDir()

	// Create .devcontainer directory and devcontainer.json.
	dcDir := filepath.Join(dir, ".devcontainer")
	if err := os.Mkdir(dcDir, 0755); err != nil {
		t.Fatal(err)
	}

	devcontainer := `{
  "name": "my-project",
  "image": "node:20-slim"
}`
	if err := os.WriteFile(filepath.Join(dcDir, "devcontainer.json"), []byte(devcontainer), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatalf("expected agentcontainer.json to be created: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, `"my-project"`) {
		t.Errorf("expected name from devcontainer, got:\n%s", content)
	}
	if !strings.Contains(content, `"node:20-slim"`) {
		t.Errorf("expected image from devcontainer, got:\n%s", content)
	}
	// Should still have default-deny agent section.
	if !strings.Contains(content, `"agent"`) {
		t.Error("expected agent key in output")
	}
}

// TestInitWithDevcontainerBuild verifies that a build section in the
// devcontainer.json is carried over.
func TestInitWithDevcontainerBuild(t *testing.T) {
	dir := t.TempDir()

	dcDir := filepath.Join(dir, ".devcontainer")
	if err := os.Mkdir(dcDir, 0755); err != nil {
		t.Fatal(err)
	}

	devcontainer := `{
  "name": "build-project",
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".."
  }
}`
	if err := os.WriteFile(filepath.Join(dcDir, "devcontainer.json"), []byte(devcontainer), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)

	if !strings.Contains(content, `"dockerfile": "Dockerfile"`) {
		t.Errorf("expected build dockerfile in output, got:\n%s", content)
	}
	if !strings.Contains(content, `"context": ".."`) {
		t.Errorf("expected build context in output, got:\n%s", content)
	}
	// Should NOT contain default image since build was specified.
	if strings.Contains(content, defaultImage) {
		t.Error("should not contain default image when build is specified")
	}
}

// TestInitExistingConfigErrors verifies that init exits with an error when
// agentcontainer.json already exists.
func TestInitExistingConfigErrors(t *testing.T) {
	dir := t.TempDir()

	// Create an existing agentcontainer.json.
	existing := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(existing, []byte(`{"name":"existing"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when agentcontainer.json already exists")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}

	// Verify the original file was not modified.
	data, _ := os.ReadFile(existing)
	if string(data) != `{"name":"existing"}` {
		t.Error("existing file should not have been modified")
	}
}

// TestInitForceOverwrites verifies that --force overwrites an existing
// agentcontainer.json.
func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()

	// Create an existing agentcontainer.json.
	existing := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(existing, []byte(`{"name":"old"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir, "--force"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --force should succeed: %v", err)
	}

	data, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if strings.Contains(content, `"old"`) {
		t.Error("file should have been overwritten")
	}
	if !strings.Contains(content, `"agent"`) {
		t.Error("overwritten file should contain agent section")
	}
}

// TestInitGeneratesValidJSONC verifies the output is valid JSON after
// stripping comments.
func TestInitGeneratesValidJSONC(t *testing.T) {
	dir := t.TempDir()

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}

	// The output contains JSONC comments. Strip them and verify the
	// remaining content is valid JSON.
	stripped := stripJSONComments(data)

	var parsed map[string]any
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("output is not valid JSONC (invalid JSON after stripping comments): %v\n\nStripped content:\n%s", err, string(stripped))
	}

	// Verify key fields exist.
	if _, ok := parsed["name"]; !ok {
		t.Error("parsed JSON missing 'name' key")
	}
	if _, ok := parsed["agent"]; !ok {
		t.Error("parsed JSON missing 'agent' key")
	}
}

// TestInitDevcontainerAtRoot verifies detection of devcontainer.json at the
// workspace root (not inside .devcontainer/).
func TestInitDevcontainerAtRoot(t *testing.T) {
	dir := t.TempDir()

	devcontainer := `{
  "name": "root-config",
  "image": "python:3.12"
}`
	if err := os.WriteFile(filepath.Join(dir, "devcontainer.json"), []byte(devcontainer), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, `"root-config"`) {
		t.Errorf("expected name from root devcontainer.json, got:\n%s", content)
	}
	if !strings.Contains(content, `"python:3.12"`) {
		t.Errorf("expected image from root devcontainer.json, got:\n%s", content)
	}
}

// TestInitDetectsComposeFiles verifies that docker-compose / compose files
// are noted in the generated output.
func TestInitDetectsComposeFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a compose file in the workspace.
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("version: '3'\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "Docker Compose") {
		t.Errorf("expected compose file detection comment, got:\n%s", content)
	}
	if !strings.Contains(content, "docker-compose.yml") {
		t.Errorf("expected compose filename in comment, got:\n%s", content)
	}
}

// TestInitDevcontainerWithComments verifies that a devcontainer.json
// containing JSONC comments can be parsed.
func TestInitDevcontainerWithComments(t *testing.T) {
	dir := t.TempDir()

	dcDir := filepath.Join(dir, ".devcontainer")
	if err := os.Mkdir(dcDir, 0755); err != nil {
		t.Fatal(err)
	}

	devcontainer := `{
  // This is a comment
  "name": "commented-project",
  /* Multi-line
     comment */
  "image": "golang:1.22"
}`
	if err := os.WriteFile(filepath.Join(dcDir, "devcontainer.json"), []byte(devcontainer), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"init", "--dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "agentcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, `"commented-project"`) {
		t.Errorf("expected name from commented devcontainer, got:\n%s", content)
	}
	if !strings.Contains(content, `"golang:1.22"`) {
		t.Errorf("expected image from commented devcontainer, got:\n%s", content)
	}
}

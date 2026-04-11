package signing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultTUFRoot(t *testing.T) {
	root := DefaultTUFRoot()
	if root == "" {
		t.Skip("cannot determine home directory")
	}
	if !strings.HasSuffix(root, filepath.Join(".sigstore", "root")) {
		t.Errorf("DefaultTUFRoot() = %q, want suffix %q", root, filepath.Join(".sigstore", "root"))
	}
}

func TestValidateTUFRoot_Valid(t *testing.T) {
	dir := t.TempDir()

	rootJSON := map[string]any{
		"signed": map[string]any{
			"_type":   "root",
			"version": 1,
		},
	}
	data, err := json.Marshal(rootJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ValidateTUFRoot(dir); err != nil {
		t.Errorf("ValidateTUFRoot() = %v, want nil", err)
	}
}

func TestValidateTUFRoot_MissingRootJSON(t *testing.T) {
	dir := t.TempDir()

	err := ValidateTUFRoot(dir)
	if err == nil {
		t.Fatal("ValidateTUFRoot() = nil, want error for missing root.json")
	}
	if !strings.Contains(err.Error(), "root.json not found") {
		t.Errorf("error = %q, want it to contain 'root.json not found'", err.Error())
	}
}

func TestValidateTUFRoot_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root.json"), []byte("not json{{{"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := ValidateTUFRoot(dir)
	if err == nil {
		t.Fatal("ValidateTUFRoot() = nil, want error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error = %q, want it to contain 'not valid JSON'", err.Error())
	}
}

func TestTUFExporter_Export(t *testing.T) {
	// Create a fake TUF root source directory.
	srcDir := t.TempDir()
	rootJSON := `{"signed":{"_type":"root","version":5}}`
	if err := os.WriteFile(filepath.Join(srcDir, "root.json"), []byte(rootJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a targets subdirectory with a file.
	targetsDir := filepath.Join(srcDir, "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetsDir, "fulcio_v1.crt.pem"), []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Override DefaultTUFRoot by setting HOME to point to our fake structure.
	// Instead, we'll use the runner to simulate cosign initialize,
	// and directly test copyDir.
	destDir := filepath.Join(t.TempDir(), "export")

	// Test copyDir directly since Export depends on cosign binary.
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(srcDir, destDir); err != nil {
		t.Fatalf("copyDir() error = %v", err)
	}

	// Verify root.json was copied.
	data, err := os.ReadFile(filepath.Join(destDir, "root.json"))
	if err != nil {
		t.Fatalf("reading exported root.json: %v", err)
	}
	if string(data) != rootJSON {
		t.Errorf("exported root.json = %q, want %q", string(data), rootJSON)
	}

	// Verify targets subdir was copied.
	data, err = os.ReadFile(filepath.Join(destDir, "targets", "fulcio_v1.crt.pem"))
	if err != nil {
		t.Fatalf("reading exported cert: %v", err)
	}
	if string(data) != "CERT" {
		t.Errorf("exported cert = %q, want %q", string(data), "CERT")
	}
}

func TestTUFExporter_ExportWithRunner(t *testing.T) {
	// Set up a fake TUF root in a temp home.
	fakeHome := t.TempDir()
	sigstoreDir := filepath.Join(fakeHome, ".sigstore", "root")
	if err := os.MkdirAll(sigstoreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rootJSON := `{"signed":{"_type":"root","version":1}}`
	if err := os.WriteFile(filepath.Join(sigstoreDir, "root.json"), []byte(rootJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Override HOME so DefaultTUFRoot() points to our fake.
	t.Setenv("HOME", fakeHome)

	// Override lookPath so cosign appears available.
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedArgs []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, name string, args []string, _ []string) ([]byte, error) {
			capturedArgs = args
			return nil, nil
		},
	}

	destDir := filepath.Join(t.TempDir(), "output")
	exporter := NewTUFExporter(WithTUFRunner(runner))

	if err := exporter.Export(context.Background(), destDir); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// Verify cosign initialize was called.
	if len(capturedArgs) != 1 || capturedArgs[0] != "initialize" {
		t.Errorf("expected cosign args [initialize], got %v", capturedArgs)
	}

	// Verify root.json was copied to destination.
	data, err := os.ReadFile(filepath.Join(destDir, "root.json"))
	if err != nil {
		t.Fatalf("reading exported root.json: %v", err)
	}
	if string(data) != rootJSON {
		t.Errorf("exported root.json = %q, want %q", string(data), rootJSON)
	}
}

func TestTUFExporter_ExportNoCosign(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) {
		return "", &notFoundError{name: file}
	}
	t.Cleanup(func() { lookPath = origLookPath })

	exporter := NewTUFExporter()
	err := exporter.Export(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("Export() = nil, want error for missing cosign")
	}
	if !strings.Contains(err.Error(), "cosign binary not found") {
		t.Errorf("error = %q, want it to contain 'cosign binary not found'", err.Error())
	}
}

// notFoundError simulates exec.ErrNotFound for testing lookPath.
type notFoundError struct {
	name string
}

func (e *notFoundError) Error() string {
	return e.name + " not found"
}

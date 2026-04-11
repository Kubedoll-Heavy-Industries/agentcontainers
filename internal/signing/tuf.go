package signing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// TUFExporter copies Sigstore TUF root metadata to a target directory.
type TUFExporter struct {
	runner cmdRunner
}

// TUFExporterOption configures a TUFExporter.
type TUFExporterOption func(*TUFExporter)

// WithTUFRunner injects a custom command runner (for testing).
func WithTUFRunner(r cmdRunner) TUFExporterOption {
	return func(e *TUFExporter) {
		e.runner = r
	}
}

// NewTUFExporter creates a new TUFExporter.
func NewTUFExporter(opts ...TUFExporterOption) *TUFExporter {
	e := &TUFExporter{
		runner: execRunner{},
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// DefaultTUFRoot returns the path to cosign's TUF root directory.
// On Linux/macOS: ~/.sigstore/root/
// On Windows: %USERPROFILE%\.sigstore\root\
func DefaultTUFRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to HOME env on Unix.
		if runtime.GOOS != "windows" {
			home = os.Getenv("HOME")
		}
		if home == "" {
			return ""
		}
	}
	return filepath.Join(home, ".sigstore", "root")
}

// Export copies TUF root metadata from the local cosign TUF cache to destDir.
// It first runs "cosign initialize" to ensure the local TUF root is fresh,
// then copies the directory tree to destDir.
func (e *TUFExporter) Export(ctx context.Context, destDir string) error {
	// Ensure cosign is available.
	if _, err := lookPath("cosign"); err != nil {
		return fmt.Errorf("tuf export: cosign binary not found on PATH")
	}

	// Run cosign initialize to refresh TUF root.
	if _, err := e.runner.Run(ctx, "cosign", []string{"initialize"}, nil); err != nil {
		return fmt.Errorf("tuf export: cosign initialize: %w", err)
	}

	// Find the TUF root source directory.
	srcDir := DefaultTUFRoot()
	if srcDir == "" {
		return fmt.Errorf("tuf export: cannot determine home directory for TUF root")
	}

	if err := ValidateTUFRoot(srcDir); err != nil {
		return fmt.Errorf("tuf export: local TUF root invalid after cosign initialize: %w", err)
	}

	// Create the destination directory.
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("tuf export: creating destination: %w", err)
	}

	// Copy the TUF root tree.
	if err := copyDir(srcDir, destDir); err != nil {
		return fmt.Errorf("tuf export: copying TUF root: %w", err)
	}

	return nil
}

// ValidateTUFRoot checks that a directory contains valid TUF root metadata.
// At minimum, root.json must exist and be valid JSON.
func ValidateTUFRoot(dir string) error {
	rootJSON := filepath.Join(dir, "root.json")
	data, err := os.ReadFile(rootJSON)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("root.json not found in %s", dir)
		}
		return fmt.Errorf("reading root.json: %w", err)
	}

	if !json.Valid(data) {
		return fmt.Errorf("root.json in %s is not valid JSON", dir)
	}

	return nil
}

// copyDir recursively copies src directory to dst.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Compute relative path and destination.
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("computing relative path: %w", err)
		}
		destPath := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}

		// Copy file contents.
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		return os.WriteFile(destPath, data, 0o644)
	})
}

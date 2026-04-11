package sbom

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// mockRunner returns a commandRunner that invokes a helper test process.
// The helper process behavior is controlled by envVar.
func mockRunner(envVar string) commandRunner {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_MODE="+envVar)
		return cmd
	}
}

// TestHelperProcess is invoked by mockRunner. It is not a real test.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("HELPER_MODE") {
	case "version_ok":
		os.Exit(0)
	case "generate_ok":
		_, _ = fmt.Fprint(os.Stdout, fakeCycloneDX)
		os.Exit(0)
	case "generate_fail":
		fmt.Fprint(os.Stderr, "scan error")
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

const fakeCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "components": [
    {"type": "library", "name": "foo", "version": "1.0.0"},
    {"type": "library", "name": "bar", "version": "2.0.0"}
  ]
}`

func TestNewBOM(t *testing.T) {
	bom, err := newBOM([]byte(fakeCycloneDX))
	if err != nil {
		t.Fatalf("newBOM() error = %v", err)
	}
	if bom.Components != 2 {
		t.Errorf("Components = %d, want 2", bom.Components)
	}
	if bom.Format != Format {
		t.Errorf("Format = %q, want %q", bom.Format, Format)
	}
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(fakeCycloneDX)))
	if bom.Digest != wantDigest {
		t.Errorf("Digest = %q, want %q", bom.Digest, wantDigest)
	}
	if bom.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
}

func TestNewBOM_InvalidJSON(t *testing.T) {
	_, err := newBOM([]byte("not json"))
	if err == nil {
		t.Fatal("newBOM() expected error for invalid JSON")
	}
}

func TestCountComponents_Empty(t *testing.T) {
	n, err := countComponents([]byte(`{"components":[]}`))
	if err != nil {
		t.Fatalf("countComponents() error = %v", err)
	}
	if n != 0 {
		t.Errorf("countComponents = %d, want 0", n)
	}
}

func TestCountComponents_NoField(t *testing.T) {
	n, err := countComponents([]byte(`{}`))
	if err != nil {
		t.Fatalf("countComponents() error = %v", err)
	}
	if n != 0 {
		t.Errorf("countComponents = %d, want 0", n)
	}
}

func TestSyftGenerator_Name(t *testing.T) {
	g := NewSyftGenerator()
	if g.Name() != "syft" {
		t.Errorf("Name() = %q, want %q", g.Name(), "syft")
	}
}

func TestSyftGenerator_Available(t *testing.T) {
	g := &SyftGenerator{runner: mockRunner("version_ok")}
	if !g.Available(context.Background()) {
		t.Error("Available() = false, want true")
	}
}

func TestSyftGenerator_Available_NotInstalled(t *testing.T) {
	g := &SyftGenerator{runner: mockRunner("not_found")}
	if g.Available(context.Background()) {
		t.Error("Available() = true, want false")
	}
}

func TestSyftGenerator_Generate(t *testing.T) {
	g := &SyftGenerator{runner: mockRunner("generate_ok")}
	bom, err := g.Generate(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if bom.Components != 2 {
		t.Errorf("Components = %d, want 2", bom.Components)
	}
}

func TestSyftGenerator_Generate_Failure(t *testing.T) {
	g := &SyftGenerator{runner: mockRunner("generate_fail")}
	_, err := g.Generate(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("Generate() expected error")
	}
}

func TestCdxgenGenerator_Name(t *testing.T) {
	g := NewCdxgenGenerator()
	if g.Name() != "cdxgen" {
		t.Errorf("Name() = %q, want %q", g.Name(), "cdxgen")
	}
}

func TestCdxgenGenerator_Available(t *testing.T) {
	g := &CdxgenGenerator{runner: mockRunner("version_ok")}
	if !g.Available(context.Background()) {
		t.Error("Available() = false, want true")
	}
}

func TestCdxgenGenerator_Available_NotInstalled(t *testing.T) {
	g := &CdxgenGenerator{runner: mockRunner("not_found")}
	if g.Available(context.Background()) {
		t.Error("Available() = true, want false")
	}
}

func TestCdxgenGenerator_Generate(t *testing.T) {
	g := &CdxgenGenerator{runner: mockRunner("generate_ok")}
	bom, err := g.Generate(context.Background(), "/some/source/dir")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if bom.Components != 2 {
		t.Errorf("Components = %d, want 2", bom.Components)
	}
}

func TestCdxgenGenerator_Generate_Failure(t *testing.T) {
	g := &CdxgenGenerator{runner: mockRunner("generate_fail")}
	_, err := g.Generate(context.Background(), "/some/source/dir")
	if err == nil {
		t.Fatal("Generate() expected error")
	}
}

func TestSyftGenerator_Generate_Context(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	g := &SyftGenerator{runner: defaultRunner}
	_, err := g.Generate(ctx, "alpine:3.19")
	if err == nil {
		t.Fatal("Generate() expected error with cancelled context")
	}
}

func TestCdxgenGenerator_Generate_Context(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	g := &CdxgenGenerator{runner: defaultRunner}
	_, err := g.Generate(ctx, "/some/dir")
	if err == nil {
		t.Fatal("Generate() expected error with cancelled context")
	}
}

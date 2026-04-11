package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// Format is the SBOM output format identifier.
const Format = "cyclonedx+json"

// BOM represents a generated Software Bill of Materials.
type BOM struct {
	Format      string    `json:"format"`
	Content     []byte    `json:"content"`
	Digest      string    `json:"digest"`
	Components  int       `json:"components"`
	GeneratedAt time.Time `json:"generatedAt"`
}

// Generator produces an SBOM for an OCI image or source directory.
type Generator interface {
	// Name returns the tool name (e.g. "syft", "cdxgen").
	Name() string

	// Available reports whether the backing tool is installed and callable.
	Available(ctx context.Context) bool

	// Generate produces a CycloneDX JSON SBOM for the given target.
	// The target is an image reference (e.g. "alpine:3.19") for syft,
	// or a source directory path for cdxgen.
	Generate(ctx context.Context, target string) (*BOM, error)
}

// newBOM constructs a BOM from raw CycloneDX JSON content.
func newBOM(content []byte) (*BOM, error) {
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	components, err := countComponents(content)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM output: %w", err)
	}
	return &BOM{
		Format:      Format,
		Content:     content,
		Digest:      digest,
		Components:  components,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

// cycloneDXEnvelope is the minimal structure needed to count components.
type cycloneDXEnvelope struct {
	Components []json.RawMessage `json:"components"`
}

// countComponents parses CycloneDX JSON to count the number of components.
func countComponents(data []byte) (int, error) {
	var env cycloneDXEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return 0, err
	}
	return len(env.Components), nil
}

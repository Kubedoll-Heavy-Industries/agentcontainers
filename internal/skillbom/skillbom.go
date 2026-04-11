// Package skillbom generates SkillBOM (Skill Bill of Materials) documents
// in CycloneDX 1.7 format for agent skill packages. A SkillBOM captures
// every component of a skill (SKILL.md, bundled scripts, assets, dependencies)
// along with a semantic content hash and required capability declarations.
package skillbom

import (
	"time"
)

// Format is the SkillBOM output format identifier.
const Format = "cyclonedx+json"

// SkillBOM represents a generated Skill Bill of Materials.
type SkillBOM struct {
	// Format is "cyclonedx+json".
	Format string `json:"format"`

	// SkillName is the name of the skill (from SKILL.md frontmatter).
	SkillName string `json:"skillName"`

	// Version is the skill version (from SKILL.md frontmatter).
	Version string `json:"version"`

	// Description is a short skill description (from SKILL.md frontmatter).
	Description string `json:"description,omitempty"`

	// Capabilities lists the declared capability identifiers the skill requires.
	Capabilities []string `json:"capabilities,omitempty"`

	// ContentHash is a SHA-256 hash of the skill's semantic content
	// (normalized name + description + sorted capabilities). Format: "sha256:<hex>".
	ContentHash string `json:"contentHash"`

	// EmbeddingVector is the semantic embedding of the skill's content,
	// produced by the model named in EmbeddingModel. When present, drift
	// detection uses cosine distance on this vector instead of binary
	// content-hash comparison.
	EmbeddingVector []float32 `json:"embeddingVector,omitempty"`

	// EmbeddingModel identifies the model used to generate EmbeddingVector
	// (e.g., "nomic-embed-text-v1.5").
	EmbeddingModel string `json:"embeddingModel,omitempty"`

	// Content is the serialized CycloneDX JSON document.
	Content []byte `json:"content"`

	// Digest is the SHA-256 hash of Content. Format: "sha256:<hex>".
	Digest string `json:"digest"`

	// Components is the number of components in the BOM.
	Components int `json:"components"`

	// GeneratedAt is the timestamp when the SkillBOM was generated.
	GeneratedAt time.Time `json:"generatedAt"`
}

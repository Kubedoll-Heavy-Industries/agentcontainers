package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SLSALevel represents a SLSA provenance level (0-4).
type SLSALevel int

const (
	// SLSALevel0 means no provenance.
	SLSALevel0 SLSALevel = 0
	// SLSALevel1 means provenance exists with a builder ID.
	SLSALevel1 SLSALevel = 1
	// SLSALevel2 means provenance from a hosted build service.
	SLSALevel2 SLSALevel = 2
	// SLSALevel3 means provenance from a specific commit with a hosted builder.
	SLSALevel3 SLSALevel = 3
	// SLSALevel4 means hermetic build with full completeness.
	SLSALevel4 SLSALevel = 4
)

// knownCIBuilders lists builder ID substrings that indicate a hosted CI system
// (used for SLSA Level 2+ determination).
var knownCIBuilders = []string{
	"github.com",
	"gitlab.com",
	"cloud.google.com/build",
	"circleci.com",
	"app.travis-ci.com",
}

// Provenance represents a SLSA v1.0 provenance attestation following the
// in-toto attestation framework.
type Provenance struct {
	// BuildType identifies the type of build
	// (e.g., "https://github.com/slsa-framework/slsa-github-generator/generic@v2").
	BuildType string `json:"buildType"`

	// Builder identifies who performed the build.
	Builder ProvenanceBuilder `json:"builder"`

	// Invocation describes the invocation parameters.
	Invocation ProvenanceInvocation `json:"invocation"`

	// Materials are the input artifacts that went into the build.
	Materials []ProvenanceMaterial `json:"materials"`

	// Metadata contains timestamps and other metadata.
	Metadata ProvenanceMetadata `json:"metadata"`
}

// ProvenanceBuilder identifies the entity that performed the build.
type ProvenanceBuilder struct {
	ID string `json:"id"`
}

// ProvenanceInvocation describes how the build was invoked.
type ProvenanceInvocation struct {
	ConfigSource ProvenanceConfigSource `json:"configSource"`
	Parameters   map[string]string      `json:"parameters,omitempty"`
}

// ProvenanceConfigSource identifies the source of the build configuration.
type ProvenanceConfigSource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// ProvenanceMaterial represents an input artifact used in the build.
type ProvenanceMaterial struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// ProvenanceMetadata holds build timestamps and completeness information.
type ProvenanceMetadata struct {
	BuildStartedOn  *time.Time             `json:"buildStartedOn,omitempty"`
	BuildFinishedOn *time.Time             `json:"buildFinishedOn,omitempty"`
	Completeness    ProvenanceCompleteness `json:"completeness"`
	Reproducible    bool                   `json:"reproducible"`
}

// ProvenanceCompleteness records which aspects of the build were fully captured.
type ProvenanceCompleteness struct {
	Parameters  bool `json:"parameters"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}

// NewProvenance creates a new Provenance with the given builder ID.
// Returns nil if builderID is empty.
func NewProvenance(builderID string) *Provenance {
	if builderID == "" {
		return nil
	}
	return &Provenance{
		Builder: ProvenanceBuilder{ID: builderID},
	}
}

// AddMaterial appends a material to the provenance's material list.
func (p *Provenance) AddMaterial(uri string, digest map[string]string) {
	p.Materials = append(p.Materials, ProvenanceMaterial{
		URI:    uri,
		Digest: digest,
	})
}

// SetBuildTimes records the build start and finish timestamps.
func (p *Provenance) SetBuildTimes(start, end time.Time) {
	s := start.UTC()
	e := end.UTC()
	p.Metadata.BuildStartedOn = &s
	p.Metadata.BuildFinishedOn = &e
}

// DetermineSLSALevel computes the SLSA level based on the provenance content.
//
// Level assignment:
//   - Level 0: no provenance (nil receiver or empty builder ID)
//   - Level 1: provenance exists with a builder ID
//   - Level 2: Level 1 + hosted build service (builder.ID contains a known CI domain)
//   - Level 3: Level 2 + build from a specific commit (configSource has a digest)
//   - Level 4: Level 3 + hermetic build (completeness.materials && completeness.environment)
func (p *Provenance) DetermineSLSALevel() SLSALevel {
	if p == nil || p.Builder.ID == "" {
		return SLSALevel0
	}

	level := SLSALevel1

	if !isHostedBuilder(p.Builder.ID) {
		return level
	}
	level = SLSALevel2

	if !hasConfigSourceDigest(p.Invocation.ConfigSource) {
		return level
	}
	level = SLSALevel3

	if p.Metadata.Completeness.Materials && p.Metadata.Completeness.Environment {
		level = SLSALevel4
	}

	return level
}

// isHostedBuilder checks if the builder ID matches a known hosted CI service.
func isHostedBuilder(builderID string) bool {
	lower := strings.ToLower(builderID)
	for _, known := range knownCIBuilders {
		if strings.Contains(lower, known) {
			return true
		}
	}
	return false
}

// hasConfigSourceDigest checks if the config source has at least one digest entry.
func hasConfigSourceDigest(cs ProvenanceConfigSource) bool {
	return len(cs.Digest) > 0
}

// ParseProvenance unmarshals JSON bytes into a Provenance and validates
// required fields.
func ParseProvenance(data []byte) (*Provenance, error) {
	if len(data) == 0 {
		return nil, errors.New("provenance: empty input")
	}

	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("provenance: invalid JSON: %w", err)
	}

	if p.Builder.ID == "" {
		return nil, errors.New("provenance: missing builder ID")
	}

	return &p, nil
}

// Marshal serializes the Provenance to indented JSON.
func (p *Provenance) Marshal() ([]byte, error) {
	if p == nil {
		return nil, errors.New("provenance: cannot marshal nil provenance")
	}
	return json.MarshalIndent(p, "", "  ")
}

package orgpolicy

import (
	"fmt"
	"math"
	"path"
	"strings"
)

// ArtifactInfo describes an OCI artifact for policy validation.
type ArtifactInfo struct {
	// Registry is the container registry hosting the artifact (e.g., "ghcr.io/myorg/image").
	Registry string

	// Signed indicates whether the artifact has a valid signature.
	Signed bool

	// SLSALevel is the SLSA provenance level of the artifact (0-4).
	SLSALevel int

	// HasSBOM indicates whether an SBOM is attached to the artifact.
	HasSBOM bool

	// DriftDistance is the semantic drift distance from the expected baseline.
	DriftDistance float64
}

// ValidateArtifact checks an artifact against the org policy and returns
// all violations found. An empty slice means the artifact is compliant.
func ValidateArtifact(policy *OrgPolicy, artifact ArtifactInfo) []error {
	if policy == nil {
		return nil
	}

	var errs []error

	if policy.RequireSignatures && !artifact.Signed {
		errs = append(errs, fmt.Errorf("artifact from %q is not signed (org policy requires signatures)", artifact.Registry))
	}

	if artifact.SLSALevel < policy.MinSLSALevel {
		errs = append(errs, fmt.Errorf("artifact SLSA level %d is below org minimum %d", artifact.SLSALevel, policy.MinSLSALevel))
	}

	if policy.RequireSBOM && !artifact.HasSBOM {
		errs = append(errs, fmt.Errorf("artifact from %q has no SBOM (org policy requires SBOM)", artifact.Registry))
	}

	if policy.MaxDriftThreshold > 0 && (math.IsNaN(artifact.DriftDistance) || artifact.DriftDistance > policy.MaxDriftThreshold) {
		errs = append(errs, fmt.Errorf("artifact drift distance is invalid or exceeds org maximum %.4f", policy.MaxDriftThreshold))
	}

	if len(policy.TrustedRegistries) > 0 && artifact.Registry != "" {
		if !matchesAnyPattern(artifact.Registry, policy.TrustedRegistries) {
			errs = append(errs, fmt.Errorf("registry %q is not in org trusted registries", artifact.Registry))
		}
	}

	return errs
}

// matchesAnyPattern checks if a registry string matches any of the given
// glob patterns. Supports trailing wildcards (e.g., "ghcr.io/myorg/*").
func matchesAnyPattern(registry string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPattern(registry, pattern) {
			return true
		}
	}
	return false
}

// matchPattern matches a registry against a single pattern.
// Supports path.Match glob syntax (e.g., "ghcr.io/myorg/*").
// As a fallback, checks prefix match for "prefix/*" patterns where
// path.Match would fail on multi-segment paths.
func matchPattern(registry, pattern string) bool {
	// Exact match.
	if registry == pattern {
		return true
	}

	// Try standard path.Match.
	if matched, err := path.Match(pattern, registry); err == nil && matched {
		return true
	}

	// Handle "prefix/*" as a prefix match for multi-segment paths.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(registry, prefix+"/") {
			return true
		}
	}

	return false
}

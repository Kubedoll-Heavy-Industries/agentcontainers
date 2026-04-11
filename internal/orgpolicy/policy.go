// Package orgpolicy implements organizational policy overlay for agentcontainer
// workspaces. It loads org-level constraints, resolves them from standard
// search paths, merges them against workspace configs, and validates artifacts.
package orgpolicy

import (
	"encoding/json"
	"fmt"
	"os"
)

// rawPolicyCheck is used to detect removed fields in policy JSON before
// unmarshaling into the canonical OrgPolicy struct.
type rawPolicyCheck struct {
	MaxAge *json.RawMessage `json:"maxAge"`
}

// OrgPolicy defines organizational constraints that workspace configurations
// must satisfy. The org policy is stricter than workspace config: deny wins.
type OrgPolicy struct {
	// RequireSignatures mandates that all OCI images must be signed.
	RequireSignatures bool `json:"requireSignatures,omitempty"`

	// MinSLSALevel is the minimum SLSA provenance level (0-4).
	MinSLSALevel int `json:"minSLSALevel,omitempty"`

	// TrustedRegistries is an allowlist of registries. Supports glob
	// patterns (e.g., "ghcr.io/myorg/*"). Empty means all registries
	// are allowed.
	TrustedRegistries []string `json:"trustedRegistries,omitempty"`

	// BannedPackages lists packages that must not appear in any SBOM.
	BannedPackages []string `json:"bannedPackages,omitempty"`

	// RequireSBOM mandates that an SBOM must be attached to all artifacts.
	RequireSBOM bool `json:"requireSBOM,omitempty"`

	// MaxDriftThreshold is the maximum acceptable semantic drift distance.
	// Zero means no drift checking.
	MaxDriftThreshold float64 `json:"maxDriftThreshold,omitempty"`

	// AllowedCapabilities lists capabilities the org allows agents to use.
	// If non-empty, only these capabilities are permitted (deny-by-default).
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`

	// DeniedCapabilities lists capabilities the org explicitly blocks.
	// Deny always wins over allow.
	DeniedCapabilities []string `json:"deniedCapabilities,omitempty"`

	// AllowedFilesystemPaths is an allowlist of filesystem paths that agents
	// may declare in their filesystem capability. When non-empty, any Read or
	// Write path that is not a sub-path of at least one entry is rejected.
	// Paths must be absolute (e.g. "/data", "/workspace").
	AllowedFilesystemPaths []string `json:"allowedFilesystemPaths,omitempty"`

	// AllowedNetworkHosts is an allowlist of hostnames that agents may declare
	// in their network egress rules. When non-empty, any host not matching an
	// entry is rejected. Supports exact hostnames and suffix wildcards
	// (e.g. "*.example.com").
	AllowedNetworkHosts []string `json:"allowedNetworkHosts,omitempty"`

	// AllowedMCPImages is an allowlist of MCP server image references.
	// Supports two matching modes:
	//   - Exact pin: "ghcr.io/myorg/tool:v1" or "ghcr.io/myorg/tool@sha256:abc..."
	//   - Namespace prefix (trailing slash): "ghcr.io/myorg/tools/" matches any
	//     image directly in that namespace (no deeper nesting).
	//
	// The "oci://" prefix is stripped before matching.
	// Empty list means all MCP images are allowed (backward-compat).
	AllowedMCPImages []string `json:"allowedMCPImages,omitempty"`
}

// DefaultPolicy returns a permissive default policy with nothing required.
func DefaultPolicy() *OrgPolicy {
	return &OrgPolicy{}
}

// LoadPolicy loads an OrgPolicy from a JSON file at the given path.
func LoadPolicy(path string) (*OrgPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading org policy: %w", err)
	}

	return parsePolicy(data)
}

// parsePolicy parses and validates policy JSON bytes.
func parsePolicy(data []byte) (*OrgPolicy, error) {
	// Reject the removed maxAge field explicitly rather than silently ignoring
	// it. This catches stale policy.json files that pre-date the PRD-017 redesign.
	var check rawPolicyCheck
	if err := json.Unmarshal(data, &check); err != nil {
		return nil, fmt.Errorf("parsing org policy: %w", err)
	}
	if check.MaxAge != nil {
		return nil, fmt.Errorf("parsing org policy: 'maxAge' field is no longer supported (PRD-017: policy freshness is tied to image freshness — rebuild the image to update the policy)")
	}

	var p OrgPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing org policy: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validating org policy: %w", err)
	}

	return &p, nil
}

// Validate checks the OrgPolicy for internal consistency.
func (p *OrgPolicy) Validate() error {
	if p.MinSLSALevel < 0 || p.MinSLSALevel > 4 {
		return fmt.Errorf("minSLSALevel must be 0-4, got %d", p.MinSLSALevel)
	}
	if p.MaxDriftThreshold < 0 {
		return fmt.Errorf("maxDriftThreshold must be >= 0, got %f", p.MaxDriftThreshold)
	}
	if len(p.AllowedMCPImages) > 0 {
		if err := ValidateAllowlistPatterns(p.AllowedMCPImages); err != nil {
			return err
		}
	}
	return nil
}

package orgpolicy

import (
	"fmt"
	"strings"
)

// MatchesMCPAllowlist checks whether an MCP image reference is permitted
// by the org policy's allowedMCPImages list.
func MatchesMCPAllowlist(imageRef string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}

	normalized := strings.TrimPrefix(imageRef, "oci://")

	for _, pattern := range allowlist {
		p := strings.TrimPrefix(pattern, "oci://")

		if strings.HasSuffix(p, "/") {
			remainder := strings.TrimPrefix(normalized, p)
			if remainder != normalized && !strings.Contains(remainder, "/") && remainder != "" {
				return true
			}
			continue
		}

		if normalized == p {
			return true
		}
	}

	return false
}

// ValidateAllowlistPatterns checks that all patterns in an allowedMCPImages
// list are valid. Rejects glob characters (*, ?) and empty strings.
func ValidateAllowlistPatterns(patterns []string) error {
	for _, p := range patterns {
		if p == "" {
			return fmt.Errorf("allowedMCPImages: empty pattern")
		}
		stripped := strings.TrimPrefix(p, "oci://")
		if strings.ContainsAny(stripped, "*?") {
			return fmt.Errorf("allowedMCPImages: glob patterns are not supported, got %q (use exact refs or namespace prefixes with trailing /)", p)
		}
	}
	return nil
}

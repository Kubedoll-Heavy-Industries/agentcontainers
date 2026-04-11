package orgpolicy

import "testing"

func TestMatchesMCPAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		imageRef  string
		allowlist []string
		want      bool
	}{
		{"empty allowlist", "ghcr.io/any/image:v1", nil, true},
		{"empty allowlist empty slice", "ghcr.io/any/image:v1", []string{}, true},
		{"exact tag match", "ghcr.io/myorg/tool:v1", []string{"ghcr.io/myorg/tool:v1"}, true},
		{"exact tag mismatch", "ghcr.io/myorg/tool:v2", []string{"ghcr.io/myorg/tool:v1"}, false},
		{"exact digest match", "ghcr.io/myorg/tool@sha256:abc123", []string{"ghcr.io/myorg/tool@sha256:abc123"}, true},
		{"exact digest mismatch", "ghcr.io/myorg/tool@sha256:def456", []string{"ghcr.io/myorg/tool@sha256:abc123"}, false},
		{"namespace prefix match", "ghcr.io/myorg/tools/server:v1", []string{"ghcr.io/myorg/tools/"}, true},
		{"namespace prefix no deeper nesting", "ghcr.io/myorg/tools/sub/server:v1", []string{"ghcr.io/myorg/tools/"}, false},
		{"namespace prefix no partial name", "ghcr.io/myorg/tools-evil:v1", []string{"ghcr.io/myorg/tools/"}, false},
		{"oci prefix on image", "oci://ghcr.io/myorg/tool:v1", []string{"ghcr.io/myorg/tool:v1"}, true},
		{"oci prefix on pattern", "ghcr.io/myorg/tool:v1", []string{"oci://ghcr.io/myorg/tool:v1"}, true},
		{"oci prefix on both", "oci://ghcr.io/myorg/tool:v1", []string{"oci://ghcr.io/myorg/tool:v1"}, true},
		{"multi pattern first", "ghcr.io/a/b:v1", []string{"ghcr.io/a/b:v1", "ghcr.io/c/d:v1"}, true},
		{"multi pattern second", "ghcr.io/c/d:v1", []string{"ghcr.io/a/b:v1", "ghcr.io/c/d:v1"}, true},
		{"multi pattern none", "ghcr.io/e/f:v1", []string{"ghcr.io/a/b:v1", "ghcr.io/c/d:v1"}, false},
		{"bare ref exact match", "ghcr.io/myorg/tool", []string{"ghcr.io/myorg/tool"}, true},
		{"bare ref no match", "ghcr.io/myorg/tool", []string{"ghcr.io/myorg/other"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesMCPAllowlist(tt.imageRef, tt.allowlist)
			if got != tt.want {
				t.Errorf("MatchesMCPAllowlist(%q, %v) = %v, want %v", tt.imageRef, tt.allowlist, got, tt.want)
			}
		})
	}
}

func TestValidateAllowlistPatterns(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
	}{
		{"valid exact tag", []string{"ghcr.io/org/img:v1"}, false},
		{"valid exact digest", []string{"ghcr.io/org/img@sha256:abc"}, false},
		{"valid namespace", []string{"ghcr.io/org/imgs/"}, false},
		{"valid bare ref", []string{"ghcr.io/org/img"}, false},
		{"glob star rejected", []string{"ghcr.io/org/*"}, true},
		{"glob question rejected", []string{"ghcr.io/org/img?"}, true},
		{"empty string rejected", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAllowlistPatterns(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAllowlistPatterns(%v) error = %v, wantErr %v", tt.patterns, err, tt.wantErr)
			}
		})
	}
}

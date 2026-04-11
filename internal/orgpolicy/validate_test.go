package orgpolicy

import (
	"math"
	"strings"
	"testing"
)

func TestValidateArtifact(t *testing.T) {
	tests := []struct {
		name        string
		policy      *OrgPolicy
		artifact    ArtifactInfo
		wantErrs    int
		errContains []string
	}{
		{
			name:     "nil policy passes everything",
			policy:   nil,
			artifact: ArtifactInfo{Registry: "docker.io/library/ubuntu"},
			wantErrs: 0,
		},
		{
			name:     "default policy passes everything",
			policy:   DefaultPolicy(),
			artifact: ArtifactInfo{Registry: "docker.io/library/ubuntu"},
			wantErrs: 0,
		},
		{
			name: "compliant artifact passes all checks",
			policy: &OrgPolicy{
				RequireSignatures: true,
				MinSLSALevel:      2,
				RequireSBOM:       true,
				MaxDriftThreshold: 0.2,
				TrustedRegistries: []string{"ghcr.io/myorg/*"},
			},
			artifact: ArtifactInfo{
				Registry:      "ghcr.io/myorg/myimage",
				Signed:        true,
				SLSALevel:     3,
				HasSBOM:       true,
				DriftDistance: 0.1,
			},
			wantErrs: 0,
		},
		{
			name: "unsigned artifact violates signature requirement",
			policy: &OrgPolicy{
				RequireSignatures: true,
			},
			artifact: ArtifactInfo{
				Registry: "docker.io/library/ubuntu",
				Signed:   false,
			},
			wantErrs:    1,
			errContains: []string{"not signed"},
		},
		{
			name: "low SLSA level violates minimum",
			policy: &OrgPolicy{
				MinSLSALevel: 3,
			},
			artifact: ArtifactInfo{
				Registry:  "docker.io/library/ubuntu",
				SLSALevel: 1,
			},
			wantErrs:    1,
			errContains: []string{"SLSA level"},
		},
		{
			name: "missing SBOM violates requirement",
			policy: &OrgPolicy{
				RequireSBOM: true,
			},
			artifact: ArtifactInfo{
				Registry: "docker.io/library/ubuntu",
				HasSBOM:  false,
			},
			wantErrs:    1,
			errContains: []string{"no SBOM"},
		},
		{
			name: "drift exceeds threshold",
			policy: &OrgPolicy{
				MaxDriftThreshold: 0.1,
			},
			artifact: ArtifactInfo{
				Registry:      "docker.io/library/ubuntu",
				DriftDistance: 0.25,
			},
			wantErrs:    1,
			errContains: []string{"drift distance"},
		},
		{
			name: "drift at zero threshold is not checked",
			policy: &OrgPolicy{
				MaxDriftThreshold: 0,
			},
			artifact: ArtifactInfo{
				Registry:      "docker.io/library/ubuntu",
				DriftDistance: 99.0,
			},
			wantErrs: 0,
		},
		{
			name: "untrusted registry violates policy",
			policy: &OrgPolicy{
				TrustedRegistries: []string{"ghcr.io/myorg/*"},
			},
			artifact: ArtifactInfo{
				Registry: "docker.io/evil/image",
			},
			wantErrs:    1,
			errContains: []string{"not in org trusted registries"},
		},
		{
			name: "trusted registry passes",
			policy: &OrgPolicy{
				TrustedRegistries: []string{"ghcr.io/myorg/*", "docker.io/library/*"},
			},
			artifact: ArtifactInfo{
				Registry: "docker.io/library/ubuntu",
			},
			wantErrs: 0,
		},
		{
			name: "exact registry match",
			policy: &OrgPolicy{
				TrustedRegistries: []string{"docker.io/library/ubuntu"},
			},
			artifact: ArtifactInfo{
				Registry: "docker.io/library/ubuntu",
			},
			wantErrs: 0,
		},
		{
			name: "empty registry skips trusted check",
			policy: &OrgPolicy{
				TrustedRegistries: []string{"ghcr.io/myorg/*"},
			},
			artifact: ArtifactInfo{
				Registry: "",
			},
			wantErrs: 0,
		},
		{
			name: "multiple violations at once",
			policy: &OrgPolicy{
				RequireSignatures: true,
				MinSLSALevel:      3,
				RequireSBOM:       true,
				MaxDriftThreshold: 0.1,
				TrustedRegistries: []string{"ghcr.io/myorg/*"},
			},
			artifact: ArtifactInfo{
				Registry:      "docker.io/evil/image",
				Signed:        false,
				SLSALevel:     0,
				HasSBOM:       false,
				DriftDistance: 0.5,
			},
			wantErrs:    5,
			errContains: []string{"not signed", "SLSA level", "no SBOM", "drift distance", "not in org trusted"},
		},
		{
			name: "SLSA level exactly at minimum passes",
			policy: &OrgPolicy{
				MinSLSALevel: 2,
			},
			artifact: ArtifactInfo{
				Registry:  "docker.io/library/ubuntu",
				SLSALevel: 2,
			},
			wantErrs: 0,
		},
		{
			name: "drift exactly at threshold passes",
			policy: &OrgPolicy{
				MaxDriftThreshold: 0.15,
			},
			artifact: ArtifactInfo{
				Registry:      "docker.io/library/ubuntu",
				DriftDistance: 0.15,
			},
			wantErrs: 0,
		},
		{
			name: "NaN drift distance treated as violation",
			policy: &OrgPolicy{
				MaxDriftThreshold: 0.5,
			},
			artifact: ArtifactInfo{
				Registry:      "docker.io/library/ubuntu",
				DriftDistance: math.NaN(),
			},
			wantErrs:    1,
			errContains: []string{"drift distance"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateArtifact(tt.policy, tt.artifact)
			if len(errs) != tt.wantErrs {
				t.Errorf("ValidateArtifact() returned %d errors, want %d", len(errs), tt.wantErrs)
				for i, err := range errs {
					t.Logf("  error[%d]: %s", i, err)
				}
				return
			}

			for _, want := range tt.errContains {
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, not found in errors", want)
				}
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		registry string
		pattern  string
		want     bool
	}{
		{"ghcr.io/myorg/image", "ghcr.io/myorg/*", true},
		{"ghcr.io/myorg/deep/path", "ghcr.io/myorg/*", true},
		{"ghcr.io/other/image", "ghcr.io/myorg/*", false},
		{"docker.io/library/ubuntu", "docker.io/library/ubuntu", true},
		{"docker.io/library/alpine", "docker.io/library/ubuntu", false},
		{"docker.io/library/ubuntu", "docker.io/library/*", true},
		{"ghcr.io/a", "ghcr.io/*", true},
	}

	for _, tt := range tests {
		t.Run(tt.registry+"_vs_"+tt.pattern, func(t *testing.T) {
			got := matchPattern(tt.registry, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.registry, tt.pattern, got, tt.want)
			}
		})
	}
}

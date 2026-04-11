package orgpolicy

import (
	"strings"
	"testing"
)

func TestIsAtLeastAsRestrictive(t *testing.T) {
	tests := []struct {
		name        string
		base        *OrgPolicy
		candidate   *OrgPolicy
		wantErr     bool
		errContains []string
	}{
		{
			name:      "nil base allows anything",
			base:      nil,
			candidate: &OrgPolicy{RequireSignatures: false},
			wantErr:   false,
		},
		{
			name:        "nil candidate treated as empty policy",
			base:        &OrgPolicy{RequireSignatures: true},
			candidate:   nil,
			wantErr:     true,
			errContains: []string{"requireSignatures"},
		},
		{
			name:      "identical policies pass",
			base:      &OrgPolicy{RequireSignatures: true, MinSLSALevel: 2},
			candidate: &OrgPolicy{RequireSignatures: true, MinSLSALevel: 2},
			wantErr:   false,
		},
		// requireSignatures
		{
			name:        "requireSignatures weakened",
			base:        &OrgPolicy{RequireSignatures: true},
			candidate:   &OrgPolicy{RequireSignatures: false},
			wantErr:     true,
			errContains: []string{"requireSignatures weakened"},
		},
		{
			name:      "requireSignatures base false candidate false ok",
			base:      &OrgPolicy{RequireSignatures: false},
			candidate: &OrgPolicy{RequireSignatures: false},
			wantErr:   false,
		},
		{
			name:      "candidate adds requireSignatures ok",
			base:      &OrgPolicy{RequireSignatures: false},
			candidate: &OrgPolicy{RequireSignatures: true},
			wantErr:   false,
		},
		// minSLSALevel
		{
			name:        "minSLSALevel weakened",
			base:        &OrgPolicy{MinSLSALevel: 3},
			candidate:   &OrgPolicy{MinSLSALevel: 1},
			wantErr:     true,
			errContains: []string{"minSLSALevel weakened"},
		},
		{
			name:      "minSLSALevel equal ok",
			base:      &OrgPolicy{MinSLSALevel: 2},
			candidate: &OrgPolicy{MinSLSALevel: 2},
			wantErr:   false,
		},
		{
			name:      "minSLSALevel raised ok",
			base:      &OrgPolicy{MinSLSALevel: 1},
			candidate: &OrgPolicy{MinSLSALevel: 3},
			wantErr:   false,
		},
		// requireSBOM
		{
			name:        "requireSBOM weakened",
			base:        &OrgPolicy{RequireSBOM: true},
			candidate:   &OrgPolicy{RequireSBOM: false},
			wantErr:     true,
			errContains: []string{"requireSBOM weakened"},
		},
		{
			name:      "requireSBOM base false ok",
			base:      &OrgPolicy{RequireSBOM: false},
			candidate: &OrgPolicy{RequireSBOM: false},
			wantErr:   false,
		},
		// maxDriftThreshold
		{
			name:        "maxDriftThreshold raised weakens",
			base:        &OrgPolicy{MaxDriftThreshold: 0.5},
			candidate:   &OrgPolicy{MaxDriftThreshold: 0.9},
			wantErr:     true,
			errContains: []string{"maxDriftThreshold weakened"},
		},
		{
			name:        "maxDriftThreshold removed weakens",
			base:        &OrgPolicy{MaxDriftThreshold: 0.5},
			candidate:   &OrgPolicy{MaxDriftThreshold: 0},
			wantErr:     true,
			errContains: []string{"maxDriftThreshold weakened"},
		},
		{
			name:      "maxDriftThreshold lowered ok",
			base:      &OrgPolicy{MaxDriftThreshold: 0.9},
			candidate: &OrgPolicy{MaxDriftThreshold: 0.3},
			wantErr:   false,
		},
		{
			name:      "maxDriftThreshold both zero ok",
			base:      &OrgPolicy{MaxDriftThreshold: 0},
			candidate: &OrgPolicy{MaxDriftThreshold: 0},
			wantErr:   false,
		},
		// bannedPackages
		{
			name:        "bannedPackages missing package weakens",
			base:        &OrgPolicy{BannedPackages: []string{"log4j", "openssl-1.0"}},
			candidate:   &OrgPolicy{BannedPackages: []string{"log4j"}},
			wantErr:     true,
			errContains: []string{"bannedPackages weakened", "openssl-1.0"},
		},
		{
			name:      "bannedPackages superset ok",
			base:      &OrgPolicy{BannedPackages: []string{"log4j"}},
			candidate: &OrgPolicy{BannedPackages: []string{"log4j", "struts"}},
			wantErr:   false,
		},
		{
			name:        "bannedPackages empty candidate weakens",
			base:        &OrgPolicy{BannedPackages: []string{"log4j"}},
			candidate:   &OrgPolicy{BannedPackages: nil},
			wantErr:     true,
			errContains: []string{"bannedPackages weakened"},
		},
		// deniedCapabilities
		{
			name:        "deniedCapabilities missing entry weakens",
			base:        &OrgPolicy{DeniedCapabilities: []string{"shell", "network"}},
			candidate:   &OrgPolicy{DeniedCapabilities: []string{"shell"}},
			wantErr:     true,
			errContains: []string{"deniedCapabilities weakened", "network"},
		},
		{
			name:      "deniedCapabilities superset ok",
			base:      &OrgPolicy{DeniedCapabilities: []string{"shell"}},
			candidate: &OrgPolicy{DeniedCapabilities: []string{"shell", "git"}},
			wantErr:   false,
		},
		// allowedCapabilities
		{
			name: "allowedCapabilities base empty means allow-all no restriction",
			base: &OrgPolicy{AllowedCapabilities: nil},
			candidate: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem"},
			},
			wantErr: false,
		},
		{
			name:        "allowedCapabilities candidate empty weakens non-empty base",
			base:        &OrgPolicy{AllowedCapabilities: []string{"filesystem"}},
			candidate:   &OrgPolicy{AllowedCapabilities: nil},
			wantErr:     true,
			errContains: []string{"allowedCapabilities weakened"},
		},
		{
			name:        "allowedCapabilities candidate adds extra capability weakens",
			base:        &OrgPolicy{AllowedCapabilities: []string{"filesystem"}},
			candidate:   &OrgPolicy{AllowedCapabilities: []string{"filesystem", "shell"}},
			wantErr:     true,
			errContains: []string{"allowedCapabilities weakened", "shell"},
		},
		{
			name:      "allowedCapabilities candidate subset ok",
			base:      &OrgPolicy{AllowedCapabilities: []string{"filesystem", "shell"}},
			candidate: &OrgPolicy{AllowedCapabilities: []string{"filesystem"}},
			wantErr:   false,
		},
		{
			name:      "allowedCapabilities identical ok",
			base:      &OrgPolicy{AllowedCapabilities: []string{"filesystem", "shell"}},
			candidate: &OrgPolicy{AllowedCapabilities: []string{"filesystem", "shell"}},
			wantErr:   false,
		},
		// allowedMCPImages
		{
			name:        "allowedMCPImages candidate empty weakens non-empty base",
			base:        &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/myorg/server:v1"}},
			candidate:   &OrgPolicy{AllowedMCPImages: nil},
			wantErr:     true,
			errContains: []string{"allowedMCPImages weakened"},
		},
		{
			name:        "allowedMCPImages candidate adds extra image weakens",
			base:        &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/myorg/server:v1"}},
			candidate:   &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/myorg/server:v1", "ghcr.io/evil/image:v1"}},
			wantErr:     true,
			errContains: []string{"allowedMCPImages weakened", "ghcr.io/evil/image:v1"},
		},
		{
			name:      "allowedMCPImages identical ok",
			base:      &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/myorg/server:v1"}},
			candidate: &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/myorg/server:v1"}},
			wantErr:   false,
		},
		{
			name:      "allowedMCPImages base empty means allow-all ok",
			base:      &OrgPolicy{AllowedMCPImages: nil},
			candidate: &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/x:v1"}},
			wantErr:   false,
		},
		// multiple weakening fields
		{
			name: "multiple weakening fields reported together",
			base: &OrgPolicy{
				RequireSignatures: true,
				MinSLSALevel:      2,
				RequireSBOM:       true,
			},
			candidate: &OrgPolicy{
				RequireSignatures: false,
				MinSLSALevel:      1,
				RequireSBOM:       false,
			},
			wantErr:     true,
			errContains: []string{"requireSignatures", "minSLSALevel", "requireSBOM"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsAtLeastAsRestrictive(tt.base, tt.candidate)
			if tt.wantErr {
				if err == nil {
					t.Fatal("IsAtLeastAsRestrictive() error = nil, want error")
				}
				for _, want := range tt.errContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("IsAtLeastAsRestrictive() error = %q, want it to contain %q", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("IsAtLeastAsRestrictive() unexpected error: %v", err)
			}
		})
	}
}

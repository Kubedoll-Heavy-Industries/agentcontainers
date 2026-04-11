package orgpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    func(t *testing.T, p *OrgPolicy)
		wantErr bool
	}{
		{
			name: "full policy",
			json: `{
				"requireSignatures": true,
				"minSLSALevel": 3,
				"trustedRegistries": ["ghcr.io/myorg/*", "docker.io/library/*"],
				"bannedPackages": ["log4j", "event-stream"],
				"requireSBOM": true,
				"maxDriftThreshold": 0.15,
				"allowedCapabilities": ["filesystem", "network", "shell"],
				"deniedCapabilities": ["git"]
			}`,
			want: func(t *testing.T, p *OrgPolicy) {
				t.Helper()
				if !p.RequireSignatures {
					t.Error("RequireSignatures = false, want true")
				}
				if p.MinSLSALevel != 3 {
					t.Errorf("MinSLSALevel = %d, want 3", p.MinSLSALevel)
				}
				if len(p.TrustedRegistries) != 2 {
					t.Errorf("len(TrustedRegistries) = %d, want 2", len(p.TrustedRegistries))
				}
				if len(p.BannedPackages) != 2 {
					t.Errorf("len(BannedPackages) = %d, want 2", len(p.BannedPackages))
				}
				if !p.RequireSBOM {
					t.Error("RequireSBOM = false, want true")
				}
				if p.MaxDriftThreshold != 0.15 {
					t.Errorf("MaxDriftThreshold = %f, want 0.15", p.MaxDriftThreshold)
				}
				if len(p.AllowedCapabilities) != 3 {
					t.Errorf("len(AllowedCapabilities) = %d, want 3", len(p.AllowedCapabilities))
				}
				if len(p.DeniedCapabilities) != 1 {
					t.Errorf("len(DeniedCapabilities) = %d, want 1", len(p.DeniedCapabilities))
				}
			},
		},
		{
			name: "empty policy",
			json: `{}`,
			want: func(t *testing.T, p *OrgPolicy) {
				t.Helper()
				if p.RequireSignatures {
					t.Error("RequireSignatures = true, want false")
				}
				if p.MinSLSALevel != 0 {
					t.Errorf("MinSLSALevel = %d, want 0", p.MinSLSALevel)
				}
				if p.RequireSBOM {
					t.Error("RequireSBOM = true, want false")
				}
			},
		},
		{
			name: "minimal policy with only signatures",
			json: `{"requireSignatures": true}`,
			want: func(t *testing.T, p *OrgPolicy) {
				t.Helper()
				if !p.RequireSignatures {
					t.Error("RequireSignatures = false, want true")
				}
				if p.MinSLSALevel != 0 {
					t.Errorf("MinSLSALevel = %d, want 0", p.MinSLSALevel)
				}
			},
		},
		{
			name:    "invalid JSON",
			json:    `{not valid}`,
			wantErr: true,
		},
		{
			name:    "invalid SLSA level too high",
			json:    `{"minSLSALevel": 5}`,
			wantErr: true,
		},
		{
			name:    "invalid SLSA level negative",
			json:    `{"minSLSALevel": -1}`,
			wantErr: true,
		},
		{
			name:    "negative drift threshold",
			json:    `{"maxDriftThreshold": -0.5}`,
			wantErr: true,
		},
		{
			name:    "maxAge field rejected",
			json:    `{"maxAge": "7d"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o644); err != nil {
				t.Fatal(err)
			}

			p, err := LoadPolicy(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("LoadPolicy() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadPolicy() error = %v", err)
			}
			tt.want(t, p)
		})
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.json")
	if err == nil {
		t.Fatal("LoadPolicy() error = nil, want error for missing file")
	}
}

func TestPolicyValidate_MaxAgeRejected(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"maxAge": "7d"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPolicy(policyPath)
	if err == nil {
		t.Fatal("LoadPolicy() error = nil, want error for maxAge field")
	}
	if !strings.Contains(err.Error(), "maxAge") {
		t.Errorf("error = %q, want it to mention 'maxAge'", err.Error())
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p == nil {
		t.Fatal("DefaultPolicy() = nil")
	}
	if p.RequireSignatures {
		t.Error("RequireSignatures = true, want false")
	}
	if p.MinSLSALevel != 0 {
		t.Errorf("MinSLSALevel = %d, want 0", p.MinSLSALevel)
	}
	if p.RequireSBOM {
		t.Error("RequireSBOM = true, want false")
	}
	if p.MaxDriftThreshold != 0 {
		t.Errorf("MaxDriftThreshold = %f, want 0", p.MaxDriftThreshold)
	}
	if len(p.AllowedCapabilities) != 0 {
		t.Errorf("len(AllowedCapabilities) = %d, want 0", len(p.AllowedCapabilities))
	}
	if len(p.DeniedCapabilities) != 0 {
		t.Errorf("len(DeniedCapabilities) = %d, want 0", len(p.DeniedCapabilities))
	}
}

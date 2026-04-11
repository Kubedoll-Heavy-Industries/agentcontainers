package signing

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewProvenance(t *testing.T) {
	tests := []struct {
		name      string
		builderID string
		wantNil   bool
	}{
		{"valid builder ID", "https://github.com/slsa-framework/slsa-github-generator/generic@v2", false},
		{"simple builder ID", "local-builder", false},
		{"empty builder ID", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvenance(tt.builderID)
			if tt.wantNil && p != nil {
				t.Error("expected nil provenance for empty builder ID")
			}
			if !tt.wantNil {
				if p == nil {
					t.Fatal("expected non-nil provenance")
				}
				if p.Builder.ID != tt.builderID {
					t.Errorf("expected builder ID %q, got %q", tt.builderID, p.Builder.ID)
				}
			}
		})
	}
}

func TestProvenanceAddMaterial(t *testing.T) {
	p := NewProvenance("test-builder")
	if len(p.Materials) != 0 {
		t.Fatalf("expected 0 materials initially, got %d", len(p.Materials))
	}

	p.AddMaterial("git+https://github.com/org/repo@refs/heads/main", map[string]string{
		"sha256": "abc123",
	})
	if len(p.Materials) != 1 {
		t.Fatalf("expected 1 material after first add, got %d", len(p.Materials))
	}
	if p.Materials[0].URI != "git+https://github.com/org/repo@refs/heads/main" {
		t.Errorf("unexpected material URI: %s", p.Materials[0].URI)
	}
	if p.Materials[0].Digest["sha256"] != "abc123" {
		t.Errorf("unexpected material digest: %v", p.Materials[0].Digest)
	}

	p.AddMaterial("pkg:golang/github.com/example/lib@v1.0.0", map[string]string{
		"sha256": "def456",
		"sha512": "789ghi",
	})
	if len(p.Materials) != 2 {
		t.Fatalf("expected 2 materials after second add, got %d", len(p.Materials))
	}
}

func TestProvenanceSetBuildTimes(t *testing.T) {
	p := NewProvenance("test-builder")
	if p.Metadata.BuildStartedOn != nil {
		t.Fatal("expected nil BuildStartedOn initially")
	}
	if p.Metadata.BuildFinishedOn != nil {
		t.Fatal("expected nil BuildFinishedOn initially")
	}

	start := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 20, 10, 5, 30, 0, time.UTC)

	p.SetBuildTimes(start, end)

	if p.Metadata.BuildStartedOn == nil {
		t.Fatal("expected non-nil BuildStartedOn after SetBuildTimes")
	}
	if p.Metadata.BuildFinishedOn == nil {
		t.Fatal("expected non-nil BuildFinishedOn after SetBuildTimes")
	}
	if !p.Metadata.BuildStartedOn.Equal(start) {
		t.Errorf("expected start time %v, got %v", start, *p.Metadata.BuildStartedOn)
	}
	if !p.Metadata.BuildFinishedOn.Equal(end) {
		t.Errorf("expected end time %v, got %v", end, *p.Metadata.BuildFinishedOn)
	}
}

func TestProvenanceSetBuildTimesConvertsToUTC(t *testing.T) {
	p := NewProvenance("test-builder")

	loc := time.FixedZone("UTC+5", 5*60*60)
	start := time.Date(2026, 2, 20, 15, 0, 0, 0, loc)
	end := time.Date(2026, 2, 20, 15, 30, 0, 0, loc)

	p.SetBuildTimes(start, end)

	if p.Metadata.BuildStartedOn.Location() != time.UTC {
		t.Error("expected BuildStartedOn in UTC")
	}
	if p.Metadata.BuildFinishedOn.Location() != time.UTC {
		t.Error("expected BuildFinishedOn in UTC")
	}
}

func TestDetermineSLSALevel(t *testing.T) {
	tests := []struct {
		name  string
		prov  *Provenance
		level SLSALevel
	}{
		{
			name:  "nil provenance is level 0",
			prov:  nil,
			level: SLSALevel0,
		},
		{
			name:  "empty builder is level 0",
			prov:  &Provenance{},
			level: SLSALevel0,
		},
		{
			name: "local builder is level 1",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "local-machine"},
			},
			level: SLSALevel1,
		},
		{
			name: "github builder without commit is level 2",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://github.com/slsa-framework/slsa-github-generator/generic@v2"},
			},
			level: SLSALevel2,
		},
		{
			name: "gitlab builder without commit is level 2",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://gitlab.com/org/project"},
			},
			level: SLSALevel2,
		},
		{
			name: "google cloud build without commit is level 2",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://cloud.google.com/build/v1"},
			},
			level: SLSALevel2,
		},
		{
			name: "github builder with commit digest is level 3",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://github.com/slsa-framework/slsa-github-generator/generic@v2"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/org/repo@refs/heads/main",
						Digest: map[string]string{"sha1": "abc123"},
					},
				},
			},
			level: SLSALevel3,
		},
		{
			name: "hermetic build is level 4",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://github.com/slsa-framework/slsa-github-generator/generic@v2"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/org/repo@refs/heads/main",
						Digest: map[string]string{"sha1": "abc123"},
					},
				},
				Metadata: ProvenanceMetadata{
					Completeness: ProvenanceCompleteness{
						Parameters:  true,
						Environment: true,
						Materials:   true,
					},
					Reproducible: true,
				},
			},
			level: SLSALevel4,
		},
		{
			name: "completeness with only materials is level 3 not 4",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://github.com/actions/runner"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/org/repo@refs/heads/main",
						Digest: map[string]string{"sha1": "def456"},
					},
				},
				Metadata: ProvenanceMetadata{
					Completeness: ProvenanceCompleteness{
						Materials: true,
					},
				},
			},
			level: SLSALevel3,
		},
		{
			name: "completeness with only environment is level 3 not 4",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://github.com/actions/runner"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/org/repo@refs/heads/main",
						Digest: map[string]string{"sha1": "def456"},
					},
				},
				Metadata: ProvenanceMetadata{
					Completeness: ProvenanceCompleteness{
						Environment: true,
					},
				},
			},
			level: SLSALevel3,
		},
		{
			name: "case insensitive builder matching",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "https://GITHUB.COM/org/builder"},
			},
			level: SLSALevel2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.prov.DetermineSLSALevel()
			if got != tt.level {
				t.Errorf("DetermineSLSALevel() = %d, want %d", got, tt.level)
			}
		})
	}
}

func TestParseProvenance(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
		check   func(t *testing.T, p *Provenance)
	}{
		{
			name: "valid provenance",
			input: `{
				"buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
				"builder": {"id": "https://github.com/actions/runner"},
				"invocation": {
					"configSource": {
						"uri": "git+https://github.com/org/repo",
						"digest": {"sha1": "abc"}
					}
				},
				"materials": [
					{"uri": "pkg:golang/mod@v1.0.0", "digest": {"sha256": "deadbeef"}}
				],
				"metadata": {
					"completeness": {"parameters": false, "environment": false, "materials": true},
					"reproducible": false
				}
			}`,
			check: func(t *testing.T, p *Provenance) {
				if p.Builder.ID != "https://github.com/actions/runner" {
					t.Errorf("unexpected builder ID: %s", p.Builder.ID)
				}
				if len(p.Materials) != 1 {
					t.Errorf("expected 1 material, got %d", len(p.Materials))
				}
				if p.Materials[0].Digest["sha256"] != "deadbeef" {
					t.Errorf("unexpected material digest: %v", p.Materials[0].Digest)
				}
				if p.DetermineSLSALevel() != SLSALevel3 {
					t.Errorf("expected level 3, got %d", p.DetermineSLSALevel())
				}
			},
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "empty input",
		},
		{
			name:    "invalid JSON",
			input:   "{not-valid-json}",
			wantErr: "invalid JSON",
		},
		{
			name:    "missing builder ID",
			input:   `{"buildType": "test", "builder": {"id": ""}}`,
			wantErr: "missing builder ID",
		},
		{
			name:    "no builder field at all",
			input:   `{"buildType": "test"}`,
			wantErr: "missing builder ID",
		},
		{
			name: "minimal valid provenance",
			input: `{
				"builder": {"id": "my-builder"},
				"metadata": {"completeness": {}}
			}`,
			check: func(t *testing.T, p *Provenance) {
				if p.Builder.ID != "my-builder" {
					t.Errorf("unexpected builder ID: %s", p.Builder.ID)
				}
				if p.DetermineSLSALevel() != SLSALevel1 {
					t.Errorf("expected level 1, got %d", p.DetermineSLSALevel())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseProvenance([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); !contains(got, tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestProvenanceMarshalRoundTrip(t *testing.T) {
	start := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 20, 10, 5, 0, 0, time.UTC)

	original := &Provenance{
		BuildType: "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
		Builder:   ProvenanceBuilder{ID: "https://github.com/actions/runner"},
		Invocation: ProvenanceInvocation{
			ConfigSource: ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
			Parameters: map[string]string{"GOFLAGS": "-trimpath"},
		},
		Materials: []ProvenanceMaterial{
			{
				URI:    "pkg:golang/github.com/example/lib@v1.0.0",
				Digest: map[string]string{"sha256": "deadbeef"},
			},
			{
				URI:    "pkg:golang/github.com/example/other@v2.1.0",
				Digest: map[string]string{"sha256": "cafebabe"},
			},
		},
		Metadata: ProvenanceMetadata{
			BuildStartedOn:  &start,
			BuildFinishedOn: &end,
			Completeness: ProvenanceCompleteness{
				Parameters:  true,
				Environment: true,
				Materials:   true,
			},
			Reproducible: true,
		},
	}

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	roundTripped, err := ParseProvenance(data)
	if err != nil {
		t.Fatalf("ParseProvenance() error: %v", err)
	}

	// Verify key fields survived the round trip.
	if roundTripped.Builder.ID != original.Builder.ID {
		t.Errorf("builder ID mismatch: got %q, want %q", roundTripped.Builder.ID, original.Builder.ID)
	}
	if roundTripped.BuildType != original.BuildType {
		t.Errorf("buildType mismatch: got %q, want %q", roundTripped.BuildType, original.BuildType)
	}
	if len(roundTripped.Materials) != len(original.Materials) {
		t.Errorf("materials count mismatch: got %d, want %d", len(roundTripped.Materials), len(original.Materials))
	}
	for i, m := range roundTripped.Materials {
		if m.URI != original.Materials[i].URI {
			t.Errorf("material[%d] URI mismatch: got %q, want %q", i, m.URI, original.Materials[i].URI)
		}
	}
	if roundTripped.Invocation.Parameters["GOFLAGS"] != "-trimpath" {
		t.Errorf("invocation parameter mismatch: got %q", roundTripped.Invocation.Parameters["GOFLAGS"])
	}
	if roundTripped.Metadata.Completeness.Materials != true {
		t.Error("completeness.materials should be true after round trip")
	}
	if roundTripped.Metadata.Completeness.Environment != true {
		t.Error("completeness.environment should be true after round trip")
	}
	if roundTripped.Metadata.Reproducible != true {
		t.Error("reproducible should be true after round trip")
	}
	if !roundTripped.Metadata.BuildStartedOn.Equal(start) {
		t.Errorf("build start time mismatch: got %v, want %v", roundTripped.Metadata.BuildStartedOn, start)
	}

	// SLSA level should also survive the round trip.
	if roundTripped.DetermineSLSALevel() != original.DetermineSLSALevel() {
		t.Errorf("SLSA level mismatch: got %d, want %d", roundTripped.DetermineSLSALevel(), original.DetermineSLSALevel())
	}
}

func TestProvenanceMarshalNil(t *testing.T) {
	var p *Provenance
	_, err := p.Marshal()
	if err == nil {
		t.Fatal("expected error marshaling nil provenance")
	}
	if got := err.Error(); !contains(got, "cannot marshal nil") {
		t.Errorf("expected 'cannot marshal nil' error, got: %v", err)
	}
}

func TestProvenanceMarshalProducesValidJSON(t *testing.T) {
	p := NewProvenance("test-builder")
	p.BuildType = "test-type"
	p.AddMaterial("pkg:test@v1.0.0", map[string]string{"sha256": "abc"})

	data, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// Verify it is valid JSON.
	if !json.Valid(data) {
		t.Errorf("Marshal() produced invalid JSON: %s", data)
	}
}

func TestSLSALevelConstants(t *testing.T) {
	// Verify level ordering.
	if SLSALevel0 >= SLSALevel1 {
		t.Error("level 0 should be less than level 1")
	}
	if SLSALevel1 >= SLSALevel2 {
		t.Error("level 1 should be less than level 2")
	}
	if SLSALevel2 >= SLSALevel3 {
		t.Error("level 2 should be less than level 3")
	}
	if SLSALevel3 >= SLSALevel4 {
		t.Error("level 3 should be less than level 4")
	}
}

func TestIsHostedBuilder(t *testing.T) {
	tests := []struct {
		name     string
		builder  string
		expected bool
	}{
		{"github", "https://github.com/org/runner", true},
		{"gitlab", "https://gitlab.com/org/runner", true},
		{"google cloud build", "https://cloud.google.com/build/v1", true},
		{"circleci", "https://circleci.com/org/proj", true},
		{"travis", "https://app.travis-ci.com/org/proj", true},
		{"local builder", "local-machine", false},
		{"custom builder", "https://mybuild.internal/runner", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHostedBuilder(tt.builder)
			if got != tt.expected {
				t.Errorf("isHostedBuilder(%q) = %v, want %v", tt.builder, got, tt.expected)
			}
		})
	}
}

// contains is a helper for checking error message substrings in tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsSubstring(s, substr)
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

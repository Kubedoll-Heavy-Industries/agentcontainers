package signing

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSLSALevelString(t *testing.T) {
	tests := []struct {
		level SLSALevel
		want  string
	}{
		{SLSALevel0, "SLSA L0 (none)"},
		{SLSALevel1, "SLSA L1 (scripted build)"},
		{SLSALevel2, "SLSA L2 (hosted build)"},
		{SLSALevel3, "SLSA L3 (hardened build)"},
		{SLSALevel4, "SLSA L4 (hermetic build)"},
		{SLSALevel(99), "SLSA L99 (unknown)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := SLSALevelString(tt.level)
			if got != tt.want {
				t.Errorf("SLSALevelString(%d) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestParseInTotoStatement(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   string
		checkProv func(t *testing.T, stmt *InTotoStatement, prov *Provenance)
	}{
		{
			name:    "empty input",
			input:   "",
			wantErr: "empty attestation data",
		},
		{
			name:    "invalid JSON",
			input:   "{not-valid",
			wantErr: "invalid in-toto statement",
		},
		{
			name:    "missing _type",
			input:   `{"predicateType": "test", "predicate": {"builder": {"id": "test"}}}`,
			wantErr: "missing _type field",
		},
		{
			name:    "missing builder in predicate",
			input:   `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "test", "predicate": {}}`,
			wantErr: "missing builder ID",
		},
		{
			name: "valid statement",
			input: `{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject": [
					{
						"name": "ghcr.io/org/image",
						"digest": {"sha256": "abc123"}
					}
				],
				"predicate": {
					"buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
					"builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"},
					"invocation": {
						"configSource": {
							"uri": "git+https://github.com/org/repo@refs/heads/main",
							"digest": {"sha1": "deadbeef"}
						}
					},
					"materials": [],
					"metadata": {
						"completeness": {"parameters": false, "environment": false, "materials": false},
						"reproducible": false
					}
				}
			}`,
			checkProv: func(t *testing.T, stmt *InTotoStatement, prov *Provenance) {
				if stmt.Type != "https://in-toto.io/Statement/v1" {
					t.Errorf("unexpected _type: %s", stmt.Type)
				}
				if len(stmt.Subject) != 1 {
					t.Errorf("expected 1 subject, got %d", len(stmt.Subject))
				}
				if stmt.Subject[0].Name != "ghcr.io/org/image" {
					t.Errorf("unexpected subject name: %s", stmt.Subject[0].Name)
				}
				if prov.Builder.ID != "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0" {
					t.Errorf("unexpected builder ID: %s", prov.Builder.ID)
				}
				if prov.DetermineSLSALevel() != SLSALevel3 {
					t.Errorf("expected SLSA L3, got L%d", prov.DetermineSLSALevel())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, prov, err := ParseInTotoStatement([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkProv != nil {
				tt.checkProv(t, stmt, prov)
			}
		})
	}
}

func TestValidateProvenance(t *testing.T) {
	baseProv := &Provenance{
		Builder: ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: ProvenanceInvocation{
			ConfigSource: ProvenanceConfigSource{
				URI:    "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123def456"},
			},
		},
		Materials: []ProvenanceMaterial{
			{
				URI:    "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123def456"},
			},
		},
		Metadata: ProvenanceMetadata{
			Completeness: ProvenanceCompleteness{
				Parameters:  true,
				Environment: true,
				Materials:   true,
			},
		},
	}

	tests := []struct {
		name    string
		prov    *Provenance
		opts    ProvenanceVerifyOptions
		wantErr string
	}{
		{
			name:    "nil provenance",
			prov:    nil,
			opts:    ProvenanceVerifyOptions{},
			wantErr: "nil provenance",
		},
		{
			name: "passes all checks",
			prov: baseProv,
			opts: ProvenanceVerifyOptions{
				ExpectedWorkflow:   "slsa-github-generator",
				ExpectedSourceRepo: "Kubedoll-Heavy-Industries/agentcontainers",
				MinSLSALevel:       SLSALevel3,
			},
		},
		{
			name: "level too low",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "local-builder"},
			},
			opts: ProvenanceVerifyOptions{
				MinSLSALevel: SLSALevel2,
			},
			wantErr: "SLSA level 1 is below minimum 2",
		},
		{
			name: "workflow mismatch",
			prov: baseProv,
			opts: ProvenanceVerifyOptions{
				ExpectedWorkflow: "totally-different-workflow",
			},
			wantErr: "does not match expected workflow",
		},
		{
			name: "source repo mismatch",
			prov: baseProv,
			opts: ProvenanceVerifyOptions{
				ExpectedSourceRepo: "completely-different/repo",
			},
			wantErr: "source repository",
		},
		{
			name: "default min level is L1 - passes for local builder",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "local-builder"},
			},
			opts: ProvenanceVerifyOptions{},
		},
		{
			name: "multiple errors joined",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "local-builder"},
			},
			opts: ProvenanceVerifyOptions{
				MinSLSALevel:       SLSALevel3,
				ExpectedWorkflow:   "github-actions",
				ExpectedSourceRepo: "org/repo",
			},
			wantErr: "SLSA level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProvenance(tt.prov, tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExtractSourceInfo(t *testing.T) {
	tests := []struct {
		name       string
		prov       *Provenance
		wantRepo   string
		wantCommit string
	}{
		{
			name:       "nil provenance",
			prov:       nil,
			wantRepo:   "",
			wantCommit: "",
		},
		{
			name: "from config source",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "test"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/org/repo@refs/heads/main",
						Digest: map[string]string{"sha1": "abc123"},
					},
				},
			},
			wantRepo:   "git+https://github.com/org/repo@refs/heads/main",
			wantCommit: "abc123",
		},
		{
			name: "from materials fallback",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "test"},
				Materials: []ProvenanceMaterial{
					{
						URI:    "git+https://github.com/org/repo@refs/tags/v1.0",
						Digest: map[string]string{"sha1": "def456"},
					},
				},
			},
			wantRepo:   "git+https://github.com/org/repo@refs/tags/v1.0",
			wantCommit: "def456",
		},
		{
			name: "config source preferred over materials",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "test"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI:    "git+https://github.com/primary/repo",
						Digest: map[string]string{"sha1": "primary123"},
					},
				},
				Materials: []ProvenanceMaterial{
					{
						URI:    "git+https://github.com/secondary/repo",
						Digest: map[string]string{"sha1": "secondary456"},
					},
				},
			},
			wantRepo:   "git+https://github.com/primary/repo",
			wantCommit: "primary123",
		},
		{
			name: "no digest in config source",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "test"},
				Invocation: ProvenanceInvocation{
					ConfigSource: ProvenanceConfigSource{
						URI: "git+https://github.com/org/repo",
					},
				},
			},
			wantRepo:   "git+https://github.com/org/repo",
			wantCommit: "",
		},
		{
			name: "non-git materials skipped",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "test"},
				Materials: []ProvenanceMaterial{
					{
						URI:    "pkg:golang/github.com/example/lib@v1.0",
						Digest: map[string]string{"sha256": "abc"},
					},
					{
						URI:    "git+https://github.com/org/repo",
						Digest: map[string]string{"sha1": "fromgit"},
					},
				},
			},
			wantRepo:   "git+https://github.com/org/repo",
			wantCommit: "fromgit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, commit := ExtractSourceInfo(tt.prov)
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
			if commit != tt.wantCommit {
				t.Errorf("commit = %q, want %q", commit, tt.wantCommit)
			}
		})
	}
}

func TestBuildVerifyAttestationArgs(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		opts     ProvenanceVerifyOptions
		contains []string
	}{
		{
			name: "basic ref",
			ref:  "ghcr.io/org/image@sha256:abc123",
			opts: ProvenanceVerifyOptions{},
			contains: []string{
				"verify-attestation",
				"--type", "slsaprovenance1",
				"ghcr.io/org/image@sha256:abc123",
			},
		},
		{
			name: "with cert issuer",
			ref:  "ghcr.io/org/image@sha256:abc123",
			opts: ProvenanceVerifyOptions{
				CertIssuer: "https://token.actions.githubusercontent.com",
			},
			contains: []string{
				"--certificate-oidc-issuer",
				"https://token.actions.githubusercontent.com",
			},
		},
		{
			name: "with expected workflow",
			ref:  "ghcr.io/org/image@sha256:abc123",
			opts: ProvenanceVerifyOptions{
				ExpectedWorkflow: "docker.yml",
			},
			contains: []string{
				"--certificate-identity-regexp",
				"docker.yml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildVerifyAttestationArgs(tt.ref, tt.opts)
			joined := joinArgs(args)
			for _, want := range tt.contains {
				if !contains(joined, want) {
					t.Errorf("args %v do not contain %q", args, want)
				}
			}
		})
	}
}

// joinArgs joins args with spaces for substring matching.
func joinArgs(args []string) string {
	result := ""
	for i, a := range args {
		if i > 0 {
			result += " "
		}
		result += a
	}
	return result
}

func TestMockProvenanceVerifier(t *testing.T) {
	buildEnd := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	prov := &Provenance{
		Builder: ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: ProvenanceInvocation{
			ConfigSource: ProvenanceConfigSource{
				URI:    "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
		Metadata: ProvenanceMetadata{
			BuildFinishedOn: &buildEnd,
		},
	}

	verifier := NewMockProvenanceVerifier(prov)

	result, err := verifier.VerifyProvenance(context.Background(),
		"ghcr.io/org/image@sha256:abc",
		ProvenanceVerifyOptions{
			MinSLSALevel: SLSALevel2,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Verified {
		t.Error("expected verified=true")
	}
	if result.SLSALevel != SLSALevel3 {
		t.Errorf("expected SLSA L3, got L%d", result.SLSALevel)
	}
	if result.BuilderID != prov.Builder.ID {
		t.Errorf("unexpected builder ID: %s", result.BuilderID)
	}
	if result.SourceCommit != "abc123" {
		t.Errorf("unexpected source commit: %s", result.SourceCommit)
	}
	if result.BuildTimestamp == nil {
		t.Error("expected non-nil build timestamp")
	} else if !result.BuildTimestamp.Equal(buildEnd) {
		t.Errorf("unexpected build timestamp: %v", result.BuildTimestamp)
	}
}

func TestMockProvenanceVerifierNilProv(t *testing.T) {
	verifier := NewMockProvenanceVerifier(nil)

	_, err := verifier.VerifyProvenance(context.Background(),
		"ghcr.io/org/image@sha256:abc",
		ProvenanceVerifyOptions{},
	)
	if err == nil {
		t.Fatal("expected error for nil provenance")
	}
	if !contains(err.Error(), "no provenance found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMockProvenanceVerifierFailing(t *testing.T) {
	verifier := NewMockProvenanceVerifierFailing("attestation not found")

	_, err := verifier.VerifyProvenance(context.Background(),
		"ghcr.io/org/image@sha256:abc",
		ProvenanceVerifyOptions{},
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "attestation not found") {
		t.Errorf("expected 'attestation not found' in error, got: %v", err)
	}
}

func TestMockProvenanceVerifierValidationFails(t *testing.T) {
	prov := &Provenance{
		Builder: ProvenanceBuilder{ID: "local-builder"},
	}
	verifier := NewMockProvenanceVerifier(prov)

	_, err := verifier.VerifyProvenance(context.Background(),
		"ghcr.io/org/image@sha256:abc",
		ProvenanceVerifyOptions{
			MinSLSALevel: SLSALevel3,
		},
	)
	if err == nil {
		t.Fatal("expected error for insufficient SLSA level")
	}
	if !contains(err.Error(), "SLSA level") {
		t.Errorf("expected SLSA level error, got: %v", err)
	}
}

func TestCosignProvenanceVerifierEmptyRef(t *testing.T) {
	verifier := NewCosignProvenanceVerifier()

	_, err := verifier.VerifyProvenance(context.Background(), "", ProvenanceVerifyOptions{})
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	if !contains(err.Error(), "empty artifact reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInTotoStatementRoundTrip(t *testing.T) {
	buildEnd := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	prov := &Provenance{
		BuildType: "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
		Builder: ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: ProvenanceInvocation{
			ConfigSource: ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
		Materials: []ProvenanceMaterial{
			{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
		Metadata: ProvenanceMetadata{
			BuildFinishedOn: &buildEnd,
			Completeness: ProvenanceCompleteness{
				Parameters:  true,
				Environment: true,
				Materials:   true,
			},
		},
	}

	predicate, err := json.Marshal(prov)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}

	stmt := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://slsa.dev/provenance/v1",
		Subject: []InTotoSubject{
			{
				Name:   "ghcr.io/org/image",
				Digest: map[string]string{"sha256": "image-digest"},
			},
		},
		Predicate: predicate,
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	gotStmt, gotProv, err := ParseInTotoStatement(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if gotStmt.Type != stmt.Type {
		t.Errorf("type mismatch: %q vs %q", gotStmt.Type, stmt.Type)
	}
	if gotProv.Builder.ID != prov.Builder.ID {
		t.Errorf("builder ID mismatch: %q vs %q", gotProv.Builder.ID, prov.Builder.ID)
	}
	if gotProv.DetermineSLSALevel() != SLSALevel4 {
		t.Errorf("expected SLSA L4, got L%d", gotProv.DetermineSLSALevel())
	}
}

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func TestAttestBasicPass(t *testing.T) {
	buildEnd := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123def"},
			},
		},
		Metadata: signing.ProvenanceMetadata{
			BuildFinishedOn: &buildEnd,
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		MinLevel: signing.SLSALevel1,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Provenance verified") {
		t.Errorf("expected 'Provenance verified' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "SLSA L3") {
		t.Errorf("expected SLSA level in output, got:\n%s", output)
	}
	if !strings.Contains(output, "slsa-github-generator") {
		t.Errorf("expected builder ID in output, got:\n%s", output)
	}
	if !strings.Contains(output, "abc123def") {
		t.Errorf("expected commit SHA in output, got:\n%s", output)
	}
	if !strings.Contains(output, "2026-03-01") {
		t.Errorf("expected build timestamp in output, got:\n%s", output)
	}
}

func TestAttestJSONOutput(t *testing.T) {
	buildEnd := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
		Metadata: signing.ProvenanceMetadata{
			BuildFinishedOn: &buildEnd,
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		MinLevel:   signing.SLSALevel1,
		OutputJSON: true,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be valid JSON.
	var jr attestJSONResult
	if err := json.Unmarshal(outBuf.Bytes(), &jr); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, outBuf.String())
	}

	if !jr.Verified {
		t.Error("expected verified=true in JSON")
	}
	if jr.SLSALevel != 3 {
		t.Errorf("expected slsa_level=3, got %d", jr.SLSALevel)
	}
	if jr.SourceCommit != "abc123" {
		t.Errorf("expected source_commit='abc123', got %q", jr.SourceCommit)
	}
	if jr.BuildTimestamp != "2026-03-01T12:00:00Z" {
		t.Errorf("expected build_timestamp='2026-03-01T12:00:00Z', got %q", jr.BuildTimestamp)
	}
	if !strings.Contains(jr.SLSALevelLabel, "hardened build") {
		t.Errorf("expected 'hardened build' in slsa_level_label, got %q", jr.SLSALevelLabel)
	}
}

func TestAttestVerificationFails(t *testing.T) {
	verifier := signing.NewMockProvenanceVerifierFailing("attestation not found in registry")

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{}, verifier)
	if err == nil {
		t.Fatal("expected error for failed verification")
	}
	if !strings.Contains(err.Error(), "attest:") {
		t.Errorf("expected 'attest:' prefix in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "attestation not found") {
		t.Errorf("expected 'attestation not found' in error, got: %v", err)
	}
}

func TestAttestMinLevelFails(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "local-builder",
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		MinLevel: signing.SLSALevel3,
	}, verifier)
	if err == nil {
		t.Fatal("expected error for insufficient SLSA level")
	}
	if !strings.Contains(err.Error(), "SLSA level") {
		t.Errorf("expected SLSA level error, got: %v", err)
	}
}

func TestAttestWithWorkflowCheck(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		ExpectedWorkflow: "slsa-github-generator",
		MinLevel:         signing.SLSALevel1,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAttestWithWorkflowMismatch(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		ExpectedWorkflow: "completely-different-workflow",
		MinLevel:         signing.SLSALevel1,
	}, verifier)
	if err == nil {
		t.Fatal("expected error for workflow mismatch")
	}
	if !strings.Contains(err.Error(), "does not match expected workflow") {
		t.Errorf("expected workflow mismatch error, got: %v", err)
	}
}

func TestAttestWithSourceRepoCheck(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		ExpectedSourceRepo: "Kubedoll-Heavy-Industries/agentcontainers",
		MinLevel:           signing.SLSALevel1,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAttestNoTimestamp(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/actions/runner",
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc123", attestOptions{
		MinLevel: signing.SLSALevel1,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if strings.Contains(output, "Built at") {
		t.Errorf("should not show 'Built at' when no timestamp, got:\n%s", output)
	}
}

func TestAttestCmdFlags(t *testing.T) {
	cmd := newAttestCmd()

	for _, flag := range []string{"workflow", "source-repo", "min-level", "cert-issuer", "json"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("expected --%s flag", flag)
		}
	}
}

func TestAttestCmdHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"attest", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("attest --help failed: %v", err)
	}

	output := outBuf.String()
	for _, expected := range []string{"SLSA", "provenance", "--workflow", "--min-level", "--json"} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in help text, got:\n%s", expected, output)
		}
	}
}

func TestAttestCmdRequiresArg(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"attest"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no arguments provided")
	}
}

func TestAttestCmdRejectsExtraArgs(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"attest", "ref1", "ref2"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for extra arguments")
	}
}

func TestAttestL3WithSourceAndCommit(t *testing.T) {
	buildEnd := time.Date(2026, 3, 2, 8, 30, 0, 0, time.UTC)
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main",
				Digest: map[string]string{"sha1": "fa21826abcdef"},
			},
		},
		Metadata: signing.ProvenanceMetadata{
			BuildFinishedOn: &buildEnd,
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/kubedoll-heavy-industries/ac-enforcer@sha256:abc123", attestOptions{
		ExpectedWorkflow:   "slsa-github-generator",
		ExpectedSourceRepo: "Kubedoll-Heavy-Industries/agentcontainers",
		MinLevel:           signing.SLSALevel2,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Provenance verified") {
		t.Errorf("expected 'Provenance verified' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "fa21826abcdef") {
		t.Errorf("expected commit SHA in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Kubedoll-Heavy-Industries/agentcontainers") {
		t.Errorf("expected source repo in output, got:\n%s", output)
	}
}

func TestAttestJSONNoTimestamp(t *testing.T) {
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/actions/runner",
		},
	}
	verifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newAttestCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runAttest(cmd, "ghcr.io/org/image@sha256:abc", attestOptions{
		OutputJSON: true,
	}, verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var jr attestJSONResult
	if err := json.Unmarshal(outBuf.Bytes(), &jr); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if jr.BuildTimestamp != "" {
		t.Errorf("expected empty build_timestamp, got %q", jr.BuildTimestamp)
	}
}

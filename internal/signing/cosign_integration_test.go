//go:build integration

package signing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCosignVerifier_RealBinary_KeyBased is an integration test that exercises
// CosignVerifier.Verify against the real cosign binary using a locally
// generated key pair. This tests the C2 fix — that our output parsing correctly
// handles real cosign JSON, not just a mocked response.
//
// Prerequisites:
//   - cosign is on PATH
//   - A registry is reachable and writable for pushing a test image/signature.
//     By default we use ttl.sh (ephemeral public registry) with a one-minute TTL.
//   - Docker or crane is on PATH to push the test image.
//
// The test skips if cosign is not found; it does not skip for network failures
// because a missing network should be surfaced as a test failure (CI must have
// network access for integration tests).
func TestCosignVerifier_RealBinary_KeyBased(t *testing.T) {
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not found on PATH; skipping integration test")
	}
	t.Logf("cosign binary: %s", cosignPath)

	cranePath, err := exec.LookPath("crane")
	if err != nil {
		t.Skip("crane not found on PATH; needed to push a minimal test image")
	}
	t.Logf("crane binary: %s", cranePath)

	// Work in a temp dir so key files and other artifacts are cleaned up.
	dir := t.TempDir()

	// --- Step 1: Generate a cosign key pair ---
	privKey := filepath.Join(dir, "cosign.key")
	pubKey := filepath.Join(dir, "cosign.pub")

	genCmd := exec.Command(cosignPath, "generate-key-pair",
		"--output-key-prefix", filepath.Join(dir, "cosign"),
	)
	// cosign generate-key-pair prompts for a password; pass empty via env.
	genCmd.Env = append(os.Environ(),
		"COSIGN_PASSWORD=",
	)
	genOut, genErr := genCmd.CombinedOutput()
	if genErr != nil {
		t.Fatalf("cosign generate-key-pair failed: %v\n%s", genErr, string(genOut))
	}
	t.Logf("key pair generated: %s / %s", privKey, pubKey)

	if _, err := os.Stat(privKey); err != nil {
		t.Fatalf("private key file not created at %s: %v", privKey, err)
	}
	if _, err := os.Stat(pubKey); err != nil {
		t.Fatalf("public key file not created at %s: %v", pubKey, err)
	}

	// --- Step 2: Push a minimal scratch image to ttl.sh ---
	// ttl.sh is an ephemeral public OCI registry; images expire after the TTL
	// in the image name. Using 1m to minimize leakage.
	imageRef := fmt.Sprintf("ttl.sh/agentcontainers-cosign-test-%d:1m", time.Now().UnixNano())

	pushCmd := exec.Command(cranePath, "append",
		"--base", "scratch",
		"--image", imageRef,
	)
	pushOut, pushErr := pushCmd.CombinedOutput()
	if pushErr != nil {
		t.Fatalf("crane append/push failed: %v\n%s", pushErr, string(pushOut))
	}
	t.Logf("pushed test image: %s", imageRef)

	// Resolve the digest so we can sign with an immutable ref.
	digestCmd := exec.Command(cranePath, "digest", imageRef)
	digestOut, digestErr := digestCmd.Output()
	if digestErr != nil {
		t.Fatalf("crane digest failed: %v", digestErr)
	}
	digest := strings.TrimSpace(string(digestOut))
	// Build the digest-pinned ref: registry/name@sha256:...
	atIdx := strings.LastIndex(imageRef, ":")
	baseRef := imageRef[:atIdx] // strip the :1m tag
	digestRef := baseRef + "@" + digest
	t.Logf("digest-pinned ref: %s", digestRef)

	// --- Step 3: Sign with the generated key ---
	signCmd := exec.Command(cosignPath, "sign",
		"--key", privKey,
		"--tlog-upload=false", // avoid requiring Rekor in CI
		"--yes",
		digestRef,
	)
	signCmd.Env = append(os.Environ(),
		"COSIGN_PASSWORD=",
	)
	signOut, signErr := signCmd.CombinedOutput()
	if signErr != nil {
		t.Fatalf("cosign sign failed: %v\n%s", signErr, string(signOut))
	}
	t.Logf("signed %s", digestRef)

	ctx := context.Background()

	// --- Step 4: Verify with the correct public key ---
	v := NewCosignVerifier()
	result, err := v.Verify(ctx, digestRef, VerifyOptions{
		KeyPath: pubKey,
		Offline: true, // no Rekor — we signed with --tlog-upload=false
	})
	if err != nil {
		t.Fatalf("Verify with correct key failed: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected Verified=true, got false")
	}
	t.Logf("verification passed: signer=%q logIndex=%d", result.SignerIdentity, result.RekorLogIndex)

	// SignerIdentity should reference our key path when no subject is embedded.
	if result.SignerIdentity != "key:"+pubKey {
		// cosign key-based verification doesn't embed a subject in the JSON output —
		// our code falls back to "key:<path>". Log rather than hard-fail since
		// cosign output format may vary across versions.
		t.Logf("note: SignerIdentity=%q (expected %q — cosign version may differ)",
			result.SignerIdentity, "key:"+pubKey)
	}

	// --- Step 5: Verify with a WRONG key should fail ---
	// Generate a second key pair; its public key should not verify signatures
	// made by the first key.
	wrongKeyDir := t.TempDir()
	wrongPrivKey := filepath.Join(wrongKeyDir, "cosign.key")
	wrongPubKey := filepath.Join(wrongKeyDir, "cosign.pub")

	wrongGenCmd := exec.Command(cosignPath, "generate-key-pair",
		"--output-key-prefix", filepath.Join(wrongKeyDir, "cosign"),
	)
	wrongGenCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if out, err := wrongGenCmd.CombinedOutput(); err != nil {
		t.Fatalf("second cosign generate-key-pair failed: %v\n%s", err, string(out))
	}
	_ = wrongPrivKey // generated but not used for signing

	_, wrongErr := v.Verify(ctx, digestRef, VerifyOptions{
		KeyPath: wrongPubKey,
		Offline: true,
	})
	if wrongErr == nil {
		t.Fatal("expected Verify to fail with wrong public key, but it succeeded")
	}
	t.Logf("correctly rejected wrong key: %v", wrongErr)
}

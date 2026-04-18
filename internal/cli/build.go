package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	archive "github.com/moby/go-archive"
	"github.com/moby/go-archive/compression"
	"github.com/moby/moby/client"
	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

// ContainerBuilder abstracts Docker image building and pushing for testability.
type ContainerBuilder interface {
	Build(ctx context.Context, cfg *config.AgentContainer, opts BuildImageOptions) (*BuildImageResult, error)
	Push(ctx context.Context, ref string) (string, error)
}

// BuildImageOptions configures the image build.
type BuildImageOptions struct {
	Tag       string
	ConfigDir string
}

// BuildImageResult contains the outcome of a build operation.
type BuildImageResult struct {
	ImageID string
	Tag     string
}

// PolicyInjector appends an org policy layer to an already-pushed image.
// The interface exists for testability.
type PolicyInjector interface {
	AppendPolicyLayer(ctx context.Context, imageRef string, policyJSON []byte, orgSignerKey ed25519.PrivateKey) (string, error)
}

// PolicyExtractor reads the org policy baked into an existing image manifest.
// It returns the DefaultPolicy (not an error) when the image has no policy layer.
// The interface exists for testability.
type PolicyExtractor interface {
	ExtractPolicy(ctx context.Context, imageRef string) (*orgpolicy.OrgPolicy, error)
}

func newBuildCmd() *cobra.Command {
	var (
		configPath         string
		tag                string
		sign               bool
		keyPath            string
		push               bool
		policyPath         string
		policySignKey      string
		overrideBasePolicy bool
	)

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the agentcontainer image",
		Long: `Build a container image from the agentcontainer.json configuration.

Uses the Dockerfile and build context specified in the config's "build" section.
Optionally pushes to a registry and signs the artifact with Sigstore cosign.

Use --policy to bake an org policy into the image as a typed OCI layer so that
workspaces derived from this base automatically inherit the policy at agentcontainer run time.

Use --org-sign-key to annotate the policy layer with a detached Ed25519
signature over the layer descriptor ({"keyid","sig","algo"} JSON). At run
time, workspaces with a trust store (ac policy trust add) will only accept
policy layers signed by a trusted org key, preventing adversaries with image
write access from injecting permissive policy overrides.

Examples:
  agentcontainer build                              # Build from auto-detected config
  agentcontainer build --tag myregistry.io/app:v1   # Build with custom tag
  agentcontainer build --push --sign                # Build, push, and sign (keyless)
  agentcontainer build --push --sign --key cosign.key  # Build, push, and sign with key
  agentcontainer build --push --policy policy.json  # Build, inject policy layer, push
  agentcontainer build --push --policy policy.json --org-sign-key org.key  # signed policy`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBuild(cmd, configPath, tag, sign, keyPath, push, policyPath, policySignKey, overrideBasePolicy)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json (auto-detected if omitted)")
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "Image tag (default: name from config)")
	cmd.Flags().BoolVar(&sign, "sign", false, "Sign the image after push using Sigstore cosign")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to cosign private key (omit for keyless signing)")
	cmd.Flags().BoolVar(&push, "push", false, "Push the image to its registry after building")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy.json to bake into the image as the final OCI layer (requires --push)")
	cmd.Flags().StringVar(&policySignKey, "org-sign-key", "", "Path to Ed25519 private key (PEM or raw seed bytes) to sign the policy layer descriptor (optional, requires --policy)")
	cmd.Flags().BoolVar(&overrideBasePolicy, "override-base-policy", false, "Skip the base-image policy weakening check (use with caution — allows replacing a stricter policy with a more permissive one)")

	return cmd
}

func runBuild(cmd *cobra.Command, configPath, tag string, sign bool, keyPath string, push bool, policyPath, policySignKey string, overrideBasePolicy bool) error {
	return runBuildWithDeps(cmd, configPath, tag, sign, keyPath, push, policyPath, policySignKey, overrideBasePolicy, nil, nil, nil, nil)
}

// runBuildWithDeps is the testable implementation that accepts injectable dependencies.
func runBuildWithDeps(cmd *cobra.Command, configPath, tag string, sign bool, keyPath string, push bool, policyPath, policySignKey string, overrideBasePolicy bool, builder ContainerBuilder, injector PolicyInjector, signer signing.Signer, extractor PolicyExtractor) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Resolve and parse config.
	var cfgDir string
	if configPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("build: %w", err)
		}
		_, resolved, err := config.Load(cwd)
		if err != nil {
			return fmt.Errorf("build: %w", err)
		}
		configPath = resolved
		cfgDir = filepath.Dir(resolved)
	} else {
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("build: resolving config path: %w", err)
		}
		configPath = absPath
		cfgDir = filepath.Dir(absPath)
	}

	cfg, err := config.ParseFile(configPath)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("build: invalid config: %w", err)
	}

	// 2. Validate: build section must exist.
	if cfg.Build == nil {
		return fmt.Errorf("build: config has no 'build' section (use 'image' with 'agentcontainer run' instead)")
	}

	// 3. Determine the image tag.
	if tag == "" {
		if cfg.Name != "" {
			tag = cfg.Name + ":latest"
		} else {
			tag = "agentcontainer:latest"
		}
	}

	// 4. Validate flag combinations.
	if sign && !push {
		return fmt.Errorf("build: --sign requires --push (signatures are stored in the registry)")
	}
	if policyPath != "" && !push {
		return fmt.Errorf("build: --policy requires --push (policy layer is appended to the registry manifest)")
	}

	// 4a. Validate and marshal the policy file early, before the build, so we
	// fail fast on a bad policy.json rather than after a long build.
	var policyJSON []byte
	if policyPath != "" {
		pol, err := orgpolicy.LoadPolicy(policyPath)
		if err != nil {
			return fmt.Errorf("build: --policy: %w", err)
		}

		// 4b. Weakening check: if the target tag already exists in the registry
		// with a baked-in policy, reject any candidate that loosens that policy.
		// We check before the build so the user gets feedback immediately.
		// --override-base-policy bypasses this check (explicit opt-out).
		if !overrideBasePolicy {
			if extractor == nil {
				extractor = &ociPolicyExtractor{}
			}
			existingPol, err := extractor.ExtractPolicy(ctx, tag)
			if err != nil {
				return fmt.Errorf("build: reading existing policy from %s: %w", tag, err)
			}
			if err := orgpolicy.IsAtLeastAsRestrictive(existingPol, pol); err != nil {
				return fmt.Errorf("build: --policy weakens the existing policy baked into %s (use --override-base-policy to force):\n%w", tag, err)
			}
		}

		policyJSON, err = json.Marshal(pol)
		if err != nil {
			return fmt.Errorf("build: marshaling policy: %w", err)
		}
	}

	// 5. Build the image.
	if builder == nil {
		builder, err = newDockerBuilder()
		if err != nil {
			return fmt.Errorf("build: %w", err)
		}
	}

	_, _ = fmt.Fprintf(out, "Building image %s...\n", tag)
	result, err := builder.Build(ctx, cfg, BuildImageOptions{
		Tag:       tag,
		ConfigDir: cfgDir,
	})
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Built image: %s (%s)\n", result.Tag, result.ImageID)

	// 6. Push if requested.
	var digest string
	if push {
		_, _ = fmt.Fprintf(out, "Pushing %s...\n", tag)
		digest, err = builder.Push(ctx, tag)
		if err != nil {
			return fmt.Errorf("build: push failed: %w", err)
		}
		_, _ = fmt.Fprintf(out, "Pushed: %s@%s\n", tag, digest)
	}

	// 6a. Append policy layer if requested (requires push).
	if len(policyJSON) > 0 {
		// Load the org signing key if provided.
		var orgSignerKey ed25519.PrivateKey
		if policySignKey != "" {
			orgSignerKey, err = loadEd25519PrivateKey(policySignKey)
			if err != nil {
				return fmt.Errorf("build: --org-sign-key: %w", err)
			}
		}

		if injector == nil {
			injector = newOCIResolver()
		}
		_, _ = fmt.Fprintf(out, "Injecting policy layer into %s...\n", tag)
		policyDigest, err := injector.AppendPolicyLayer(ctx, tag, policyJSON, orgSignerKey)
		if err != nil {
			return fmt.Errorf("build: injecting policy layer: %w", err)
		}
		// Update digest so signing covers the manifest that includes the policy layer.
		digest = policyDigest
		if orgSignerKey != nil {
			_, _ = fmt.Fprintf(out, "Policy layer injected (signed): %s@%s\n", tag, digest)
		} else {
			_, _ = fmt.Fprintf(out, "Policy layer injected: %s@%s\n", tag, digest)
		}
	}

	// 7. Sign if requested.
	if sign {
		if signer == nil {
			signer = signing.NewCosignSigner()
		}

		ref := tag + "@" + digest
		_, _ = fmt.Fprintf(out, "Signing %s...\n", ref)

		signResult, err := signer.Sign(ctx, ref, signing.SignOptions{
			KeyPath: keyPath,
		})
		if err != nil {
			return fmt.Errorf("build: signing failed: %w", err)
		}

		_, _ = fmt.Fprintf(out, "Signed: %s\n", signResult.Ref)
		if signResult.RekorLogIndex >= 0 {
			_, _ = fmt.Fprintf(out, "Rekor log index: %d\n", signResult.RekorLogIndex)
		}
	}

	return nil
}

// dockerBuilder implements ContainerBuilder using the Docker Engine API.
type dockerBuilder struct {
	cli client.APIClient
}

func newDockerBuilder() (*dockerBuilder, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("creating Docker client: %w", err)
	}
	return &dockerBuilder{cli: c}, nil
}

func (b *dockerBuilder) Build(ctx context.Context, cfg *config.AgentContainer, opts BuildImageOptions) (*BuildImageResult, error) {
	dockerfile := cfg.Build.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}

	buildCtx := cfg.Build.Context
	if buildCtx == "" {
		buildCtx = "."
	}

	// Resolve relative paths against the config directory.
	if !filepath.IsAbs(buildCtx) {
		buildCtx = filepath.Join(opts.ConfigDir, buildCtx)
	}

	dockerfilePath := dockerfile
	if !filepath.IsAbs(dockerfilePath) {
		dockerfilePath = filepath.Join(buildCtx, dockerfilePath)
	}

	// Create build context tar using moby's archive package.
	tar, err := archive.Tar(buildCtx, compression.None)
	if err != nil {
		return nil, fmt.Errorf("creating build context: %w", err)
	}
	defer tar.Close() //nolint:errcheck

	// Compute the relative dockerfile path within the context.
	relDockerfile, err := filepath.Rel(buildCtx, dockerfilePath)
	if err != nil {
		relDockerfile = "Dockerfile"
	}

	// Convert build args from map[string]string to map[string]*string.
	var buildArgs map[string]*string
	if len(cfg.Build.Args) > 0 {
		buildArgs = make(map[string]*string, len(cfg.Build.Args))
		for k, v := range cfg.Build.Args {
			buildArgs[k] = &v
		}
	}

	resp, err := b.cli.ImageBuild(ctx, tar, client.ImageBuildOptions{
		Dockerfile: relDockerfile,
		Tags:       []string{opts.Tag},
		BuildArgs:  buildArgs,
		Remove:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("building image: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	imageID, err := parseBuildOutput(resp.Body)
	if err != nil {
		return nil, err
	}

	return &BuildImageResult{
		ImageID: imageID,
		Tag:     opts.Tag,
	}, nil
}

func (b *dockerBuilder) Push(ctx context.Context, ref string) (string, error) {
	resp, err := b.cli.ImagePush(ctx, ref, client.ImagePushOptions{})
	if err != nil {
		return "", fmt.Errorf("pushing image: %w", err)
	}
	defer resp.Close() //nolint:errcheck

	digest, err := parsePushOutput(resp)
	if err != nil {
		return "", err
	}

	return digest, nil
}

// parseBuildOutput reads the Docker build JSON stream and extracts the image ID.
func parseBuildOutput(r io.Reader) (string, error) {
	decoder := json.NewDecoder(r)
	var imageID string

	for decoder.More() {
		var msg struct {
			Stream string `json:"stream"`
			Aux    struct {
				ID string `json:"ID"`
			} `json:"aux"`
			Error string `json:"error"`
		}
		if err := decoder.Decode(&msg); err != nil {
			return "", fmt.Errorf("parsing build output: %w", err)
		}
		if msg.Error != "" {
			return "", fmt.Errorf("build error: %s", msg.Error)
		}
		if msg.Aux.ID != "" {
			imageID = msg.Aux.ID
		}
	}

	if imageID == "" {
		return "sha256:unknown", nil
	}
	return imageID, nil
}

// ociPolicyExtractor is the production PolicyExtractor that reads the org
// policy layer from a registry image using the standard OCI resolver.
type ociPolicyExtractor struct{}

func (e *ociPolicyExtractor) ExtractPolicy(ctx context.Context, imageRef string) (*orgpolicy.OrgPolicy, error) {
	return orgpolicy.ExtractPolicy(ctx, imageRef)
}

// loadEd25519PrivateKey reads an Ed25519 private key from the given path.
// It accepts two formats:
//   - PKCS#8 DER-encoded, wrapped in a "PRIVATE KEY" PEM block (standard Go output)
//   - Raw 32-byte seed (for keys generated by simple tooling)
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	// Try PEM first.
	block, _ := pem.Decode(data)
	if block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PEM private key: %w", err)
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an Ed25519 private key (got %T)", key)
		}
		return ed, nil
	}

	// Fallback: raw 32-byte seed.
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}

	return nil, fmt.Errorf("unrecognized key format in %q: expected PEM PRIVATE KEY block or %d-byte raw seed", path, ed25519.SeedSize)
}

// parsePushOutput reads the Docker push JSON stream and extracts the digest.
func parsePushOutput(r io.Reader) (string, error) {
	decoder := json.NewDecoder(r)
	var digest string

	for decoder.More() {
		var msg struct {
			Aux struct {
				Digest string `json:"Digest"`
			} `json:"aux"`
			Error string `json:"error"`
		}
		if err := decoder.Decode(&msg); err != nil {
			return "", fmt.Errorf("parsing push output: %w", err)
		}
		if msg.Error != "" {
			return "", fmt.Errorf("push error: %s", msg.Error)
		}
		if msg.Aux.Digest != "" {
			digest = msg.Aux.Digest
		}
	}

	if digest == "" {
		return "", fmt.Errorf("no digest in push output")
	}
	return digest, nil
}

package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"github.com/moby/moby/client"
	"github.com/spf13/cobra"
)

// PackageType represents the source package manager for a shim target.
type PackageType string

const (
	PackageTypeNPM  PackageType = "npm"
	PackageTypePyPI PackageType = "pypi"
	PackageTypeGit  PackageType = "git"
)

// ShimConfig holds the parsed and validated parameters for a shim operation.
type ShimConfig struct {
	// PackageRef is the raw package reference (e.g. "@modelcontextprotocol/server-github").
	PackageRef string
	// PackageName is the cleaned package name (no version specifier).
	PackageName string
	// PackageVersion is the resolved version ("latest" if unspecified).
	PackageVersion string
	// Type is the detected or specified package manager type.
	Type PackageType
	// OutputTag is the Docker image tag for the built image.
	OutputTag string
	// BaseImage is the base Docker image to use.
	BaseImage string
	// RepoURL is the git clone URL (only set for PackageTypeGit).
	RepoURL string
	// GitRef is the branch/tag/commit to checkout (only set for PackageTypeGit).
	GitRef string
	// EntrypointOverride is a user-specified entrypoint (--entrypoint flag).
	EntrypointOverride string
}

// defaultBaseImages maps package types to their default base images.
var defaultBaseImages = map[PackageType]string{
	PackageTypeNPM:  "node:22-alpine",
	PackageTypePyPI: "python:3.12-alpine",
	PackageTypeGit:  "node:22-alpine",
}

// ImageBuilder abstracts Docker image building so that the real Docker
// client can be swapped out in tests.
type ImageBuilder interface {
	// Build creates a Docker image from the given Dockerfile content and
	// tags it with the specified tag. Build output is written to w.
	Build(ctx context.Context, dockerfile string, tag string, w io.Writer) error
}

// dockerImageBuilder implements ImageBuilder using the moby Docker SDK.
type dockerImageBuilder struct{}

// Build creates a tar archive containing the Dockerfile, sends it to the
// Docker daemon via ImageBuild, streams the output to w, and returns any error.
func (b *dockerImageBuilder) Build(ctx context.Context, dockerfile string, tag string, w io.Writer) error {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("creating Docker client: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	buildCtx, err := buildContextTar(dockerfile)
	if err != nil {
		return fmt.Errorf("creating build context: %w", err)
	}

	resp, err := cli.ImageBuild(ctx, buildCtx, client.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: "Dockerfile",
		Remove:     true,
	})
	if err != nil {
		return fmt.Errorf("docker image build: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("reading build output: %w", err)
	}

	return nil
}

// buildContextTar creates a tar archive in memory containing a single
// Dockerfile with the given content.
func buildContextTar(dockerfile string) (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	header := &tar.Header{
		Name: "Dockerfile",
		Mode: 0644,
		Size: int64(len(dockerfile)),
	}
	if err := tw.WriteHeader(header); err != nil {
		return nil, fmt.Errorf("writing tar header: %w", err)
	}
	if _, err := tw.Write([]byte(dockerfile)); err != nil {
		return nil, fmt.Errorf("writing tar body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar writer: %w", err)
	}

	return &buf, nil
}

// shimBuilder is the ImageBuilder used by the shim command. It defaults to
// the real Docker SDK builder but can be overridden in tests.
var shimBuilder ImageBuilder = &dockerImageBuilder{}

func newShimCmd() *cobra.Command {
	var (
		pkgType    string
		outputTag  string
		baseImage  string
		entrypoint string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "shim <package-reference>",
		Short: "Wrap an MCP server package as an OCI container image",
		Long: `Take an MCP server reference from npm, PyPI, or a git repository and produce
a container image suitable for use in an agentcontainer environment.

The package reference can include an optional type prefix:
  ac shim npm:@modelcontextprotocol/server-github@1.2.3
  ac shim pypi:mcp-server-fetch@0.6.2
  ac shim git:https://github.com/user/mcp-server.git@v1.0
  ac shim @modelcontextprotocol/server-github   (auto-detects npm)
  ac shim mcp-server-fetch                      (auto-detects pypi)
  ac shim https://github.com/user/repo.git      (auto-detects git)

For git sources, use @ref to specify a branch, tag, or commit:
  ac shim git:https://github.com/user/repo.git@main
  ac shim git:https://github.com/user/repo.git@v1.0.0

Use --entrypoint to override the default entry point for git sources.
Use --dry-run to generate and print the Dockerfile without building.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShim(cmd, args[0], pkgType, outputTag, baseImage, entrypoint, dryRun)
		},
	}

	cmd.Flags().StringVarP(&pkgType, "type", "t", "", "Package type: npm, pypi, git (auto-detected if omitted)")
	cmd.Flags().StringVarP(&outputTag, "output", "o", "", "Output image tag (default: mcp-<name>:latest)")
	cmd.Flags().StringVar(&baseImage, "base", "", "Base image (default: node:22-alpine for npm/git, python:3.12-alpine for pypi)")
	cmd.Flags().StringVar(&entrypoint, "entrypoint", "", "Override the default entry point (useful for git sources)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the generated Dockerfile without building the image")

	return cmd
}

func runShim(cmd *cobra.Command, ref, pkgType, outputTag, baseImage, entrypoint string, dryRun bool) error {
	out := cmd.OutOrStdout()

	cfg, err := parseShimRef(ref, pkgType)
	if err != nil {
		return fmt.Errorf("shim: %w", err)
	}

	// Apply flag overrides.
	if outputTag != "" {
		cfg.OutputTag = outputTag
	}
	if baseImage != "" {
		cfg.BaseImage = baseImage
	}
	if entrypoint != "" {
		cfg.EntrypointOverride = entrypoint
	}

	// Generate Dockerfile content.
	dockerfile, err := generateDockerfile(cfg)
	if err != nil {
		return fmt.Errorf("shim: generating Dockerfile: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Package:    %s@%s\n", cfg.PackageName, cfg.PackageVersion)
	_, _ = fmt.Fprintf(out, "Type:       %s\n", cfg.Type)
	_, _ = fmt.Fprintf(out, "Base image: %s\n", cfg.BaseImage)
	_, _ = fmt.Fprintf(out, "Output tag: %s\n", cfg.OutputTag)
	_, _ = fmt.Fprintln(out, "")

	if dryRun {
		_, _ = fmt.Fprintln(out, "Generated Dockerfile:")
		_, _ = fmt.Fprintln(out, "---")
		_, _ = fmt.Fprint(out, dockerfile)
		_, _ = fmt.Fprintln(out, "---")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Building image %s ...\n", cfg.OutputTag)

	if err := shimBuilder.Build(cmd.Context(), dockerfile, cfg.OutputTag, out); err != nil {
		return fmt.Errorf("shim: building image: %w", err)
	}

	_, _ = fmt.Fprintf(out, "\nImage built: %s\n", cfg.OutputTag)
	return nil
}

// parseShimRef parses a package reference string into a ShimConfig.
// It handles type prefixes (npm:, pypi:, git:) and version specifiers (@version).
func parseShimRef(ref, explicitType string) (*ShimConfig, error) {
	if ref == "" {
		return nil, fmt.Errorf("package reference must not be empty")
	}

	cfg := &ShimConfig{
		PackageRef: ref,
	}

	// Strip type prefix if present.
	nameWithVersion := ref
	if explicitType != "" {
		pt, err := parsePackageType(explicitType)
		if err != nil {
			return nil, err
		}
		cfg.Type = pt
	} else {
		// Check for type prefix in the reference itself.
		if after, found := strings.CutPrefix(ref, "npm:"); found {
			cfg.Type = PackageTypeNPM
			nameWithVersion = after
		} else if after, found := strings.CutPrefix(ref, "pypi:"); found {
			cfg.Type = PackageTypePyPI
			nameWithVersion = after
		} else if after, found := strings.CutPrefix(ref, "git:"); found {
			cfg.Type = PackageTypeGit
			nameWithVersion = after
		} else {
			// Auto-detect from reference format.
			cfg.Type = detectPackageType(ref)
		}
	}

	if cfg.Type == PackageTypeGit {
		cfg.RepoURL, cfg.GitRef = splitGitURLRef(nameWithVersion)
		cfg.PackageName = repoNameFromURL(cfg.RepoURL)
		if cfg.GitRef != "" {
			cfg.PackageVersion = cfg.GitRef
		} else {
			cfg.PackageVersion = "latest"
		}
	} else {
		// Parse name and version.
		cfg.PackageName, cfg.PackageVersion = splitNameVersion(nameWithVersion, cfg.Type)
	}

	// Set defaults.
	if base, ok := defaultBaseImages[cfg.Type]; ok {
		cfg.BaseImage = base
	}

	cfg.OutputTag = defaultOutputTag(cfg.PackageName)

	return cfg, nil
}

// parsePackageType converts a string flag value to a PackageType.
func parsePackageType(s string) (PackageType, error) {
	switch strings.ToLower(s) {
	case "npm":
		return PackageTypeNPM, nil
	case "pypi":
		return PackageTypePyPI, nil
	case "git":
		return PackageTypeGit, nil
	default:
		return "", fmt.Errorf("unsupported package type %q: must be npm, pypi, or git", s)
	}
}

// detectPackageType guesses the package type from the reference string.
// - @ prefix (scoped package) or contains no hyphens after a dot → npm
// - .git suffix or contains github.com/gitlab.com → git
// - Otherwise → pypi
func detectPackageType(ref string) PackageType {
	// Scoped npm packages start with @.
	if strings.HasPrefix(ref, "@") {
		return PackageTypeNPM
	}

	// Git URLs: .git suffix, or known git hosting domains.
	if strings.HasSuffix(ref, ".git") ||
		strings.Contains(ref, "github.com") ||
		strings.Contains(ref, "gitlab.com") ||
		strings.Contains(ref, "bitbucket.org") {
		return PackageTypeGit
	}

	// If it contains a slash but is not a git URL, likely npm.
	if strings.Contains(ref, "/") {
		return PackageTypeNPM
	}

	// Default to pypi for bare names (e.g. "mcp-server-fetch").
	return PackageTypePyPI
}

// splitNameVersion splits a package reference into name and version.
// For npm scoped packages like @scope/name@version, it correctly handles
// the leading @ in the scope.
func splitNameVersion(ref string, pt PackageType) (string, string) {
	switch pt {
	case PackageTypeNPM:
		return splitNPMNameVersion(ref)
	case PackageTypePyPI:
		return splitPyPINameVersion(ref)
	default:
		return ref, "latest"
	}
}

// splitNPMNameVersion handles npm package references which may be scoped (@scope/name@version).
func splitNPMNameVersion(ref string) (string, string) {
	// For scoped packages, find the version separator after the scope.
	if strings.HasPrefix(ref, "@") {
		// @scope/name@version — find the second @.
		rest := ref[1:] // strip leading @
		if idx := strings.Index(rest, "@"); idx >= 0 {
			return ref[:idx+1], rest[idx+1:]
		}
		return ref, "latest"
	}

	// Unscoped: name@version.
	if idx := strings.LastIndex(ref, "@"); idx >= 0 {
		return ref[:idx], ref[idx+1:]
	}
	return ref, "latest"
}

// splitPyPINameVersion handles PyPI package references which use @ or == as version separators.
func splitPyPINameVersion(ref string) (string, string) {
	// Support pip-style == separator.
	if idx := strings.Index(ref, "=="); idx >= 0 {
		return ref[:idx], ref[idx+2:]
	}
	// Support @ separator.
	if idx := strings.LastIndex(ref, "@"); idx >= 0 {
		return ref[:idx], ref[idx+1:]
	}
	return ref, "latest"
}

// splitGitURLRef splits a git URL reference into the clone URL and an optional ref.
// The ref is separated by @ at the end: https://github.com/user/repo.git@v1.0
// For SSH URLs like git@github.com:user/repo.git@v1.0, it splits on the last @
// only if it appears after ".git".
func splitGitURLRef(ref string) (string, string) {
	// Look for .git@ which marks the boundary between URL and ref.
	if idx := strings.Index(ref, ".git@"); idx >= 0 {
		return ref[:idx+4], ref[idx+5:]
	}

	// For URLs without .git suffix, split on the last @ that is not part of
	// an SSH user (git@host:...). If the URL contains "://" it's HTTPS and
	// we can split on the last @.
	if strings.Contains(ref, "://") {
		if idx := strings.LastIndex(ref, "@"); idx >= 0 {
			return ref[:idx], ref[idx+1:]
		}
	}

	return ref, ""
}

// repoNameFromURL extracts the repository name from a git URL.
// e.g. "https://github.com/user/mcp-server.git" -> "mcp-server"
//
//	"git@github.com:user/my-repo.git" -> "my-repo"
func repoNameFromURL(url string) string {
	// Strip trailing .git
	clean := strings.TrimSuffix(url, ".git")
	// Take the last path segment.
	if idx := strings.LastIndex(clean, "/"); idx >= 0 {
		return clean[idx+1:]
	}
	// SSH format: git@github.com:user/repo
	if idx := strings.LastIndex(clean, ":"); idx >= 0 {
		part := clean[idx+1:]
		if slashIdx := strings.LastIndex(part, "/"); slashIdx >= 0 {
			return part[slashIdx+1:]
		}
		return part
	}
	return clean
}

// defaultOutputTag generates the default Docker image tag from a package name.
// It strips the scope prefix and prefixes with "mcp-".
func defaultOutputTag(name string) string {
	clean := name
	// Strip npm scope.
	if idx := strings.LastIndex(clean, "/"); idx >= 0 {
		clean = clean[idx+1:]
	}
	// Remove any "mcp-" or "server-" prefix duplication.
	if !strings.HasPrefix(clean, "mcp-") {
		clean = "mcp-" + clean
	}
	return clean + ":latest"
}

// Dockerfile templates for npm and pypi packages.

var npmDockerfileTemplate = template.Must(template.New("npm").Parse(`# Generated by ac shim
# Source: npm:{{.PackageName}}@{{.PackageVersion}}
FROM {{.BaseImage}} AS runtime

LABEL org.opencontainers.image.title="{{.PackageName}}"
LABEL org.opencontainers.image.version="{{.PackageVersion}}"
LABEL org.opencontainers.image.created="{{.Timestamp}}"
LABEL dev.agentcontainers.mcp.transport="stdio"
LABEL dev.agentcontainers.mcp.source-registry="npm"
LABEL dev.agentcontainers.mcp.source-identifier="{{.PackageName}}@{{.PackageVersion}}"

RUN addgroup -g 1000 mcpuser && \
    adduser -u 1000 -G mcpuser -s /bin/sh -D mcpuser

RUN npm install -g {{.PackageName}}@{{.PackageVersion}} --ignore-scripts && \
    npm cache clean --force

USER mcpuser
WORKDIR /home/mcpuser

ENTRYPOINT ["{{.Entrypoint}}"]
`))

var pypiDockerfileTemplate = template.Must(template.New("pypi").Parse(`# Generated by ac shim
# Source: pypi:{{.PackageName}}@{{.PackageVersion}}
FROM {{.BaseImage}} AS runtime

LABEL org.opencontainers.image.title="{{.PackageName}}"
LABEL org.opencontainers.image.version="{{.PackageVersion}}"
LABEL org.opencontainers.image.created="{{.Timestamp}}"
LABEL dev.agentcontainers.mcp.transport="stdio"
LABEL dev.agentcontainers.mcp.source-registry="pypi"
LABEL dev.agentcontainers.mcp.source-identifier="{{.PackageName}}@{{.PackageVersion}}"

RUN addgroup -g 1000 mcpuser && \
    adduser -u 1000 -G mcpuser -s /bin/sh -D mcpuser

RUN pip install --no-cache-dir {{.PackageName}}=={{.PackageVersion}}

USER mcpuser
WORKDIR /home/mcpuser

ENTRYPOINT ["{{.Entrypoint}}"]
`))

var gitDockerfileTemplate = template.Must(template.New("git").Parse(`# Generated by ac shim
# Source: git:{{.RepoURL}}@{{.GitRef}}
FROM {{.BaseImage}} AS runtime

LABEL org.opencontainers.image.title="{{.PackageName}}"
LABEL org.opencontainers.image.version="{{.PackageVersion}}"
LABEL org.opencontainers.image.created="{{.Timestamp}}"
LABEL dev.agentcontainers.mcp.transport="stdio"
LABEL dev.agentcontainers.mcp.source-registry="git"
LABEL dev.agentcontainers.mcp.source-identifier="{{.RepoURL}}@{{.GitRef}}"

RUN apk add --no-cache git

RUN addgroup -g 1000 mcpuser && \
    adduser -u 1000 -G mcpuser -s /bin/sh -D mcpuser

WORKDIR /app
RUN git clone --depth 1{{if .GitRef}} --branch {{.GitRef}}{{end}} {{.RepoURL}} .

RUN npm install --production --ignore-scripts && \
    npm cache clean --force

USER mcpuser

ENTRYPOINT ["node", "{{.Entrypoint}}"]
`))

// gitDockerfileData holds the template data for generating git Dockerfiles.
type gitDockerfileData struct {
	PackageName    string
	PackageVersion string
	BaseImage      string
	RepoURL        string
	GitRef         string
	Entrypoint     string
	Timestamp      string
}

// dockerfileData holds the template data for generating Dockerfiles.
type dockerfileData struct {
	PackageName    string
	PackageVersion string
	BaseImage      string
	Entrypoint     string
	Timestamp      string
}

// generateDockerfile creates a Dockerfile from the ShimConfig.
func generateDockerfile(cfg *ShimConfig) (string, error) {
	return generateDockerfileWithTimestamp(cfg, time.Now().UTC().Format(time.RFC3339))
}

// generateDockerfileWithTimestamp creates a Dockerfile with a specific timestamp (for testing).
func generateDockerfileWithTimestamp(cfg *ShimConfig, timestamp string) (string, error) {
	var buf bytes.Buffer

	switch cfg.Type {
	case PackageTypeNPM:
		data := dockerfileData{
			PackageName:    cfg.PackageName,
			PackageVersion: cfg.PackageVersion,
			BaseImage:      cfg.BaseImage,
			Entrypoint:     defaultEntrypoint(cfg),
			Timestamp:      timestamp,
		}
		if err := npmDockerfileTemplate.Execute(&buf, data); err != nil {
			return "", fmt.Errorf("executing template: %w", err)
		}
	case PackageTypePyPI:
		data := dockerfileData{
			PackageName:    cfg.PackageName,
			PackageVersion: cfg.PackageVersion,
			BaseImage:      cfg.BaseImage,
			Entrypoint:     defaultEntrypoint(cfg),
			Timestamp:      timestamp,
		}
		if err := pypiDockerfileTemplate.Execute(&buf, data); err != nil {
			return "", fmt.Errorf("executing template: %w", err)
		}
	case PackageTypeGit:
		data := gitDockerfileData{
			PackageName:    cfg.PackageName,
			PackageVersion: cfg.PackageVersion,
			BaseImage:      cfg.BaseImage,
			RepoURL:        cfg.RepoURL,
			GitRef:         cfg.GitRef,
			Entrypoint:     defaultEntrypoint(cfg),
			Timestamp:      timestamp,
		}
		if err := gitDockerfileTemplate.Execute(&buf, data); err != nil {
			return "", fmt.Errorf("executing template: %w", err)
		}
	default:
		return "", fmt.Errorf("no Dockerfile template for package type %q", cfg.Type)
	}

	return buf.String(), nil
}

// defaultEntrypoint returns the default entrypoint binary for a package.
// For npm packages, it uses the binary name. For PyPI, it uses the package name
// (which typically installs a console_scripts entry point with that name).
// For git packages, it defaults to "index.js".
// If EntrypointOverride is set, it is always used.
func defaultEntrypoint(cfg *ShimConfig) string {
	if cfg.EntrypointOverride != "" {
		return cfg.EntrypointOverride
	}

	switch cfg.Type {
	case PackageTypeNPM:
		// Use the package name as the binary. For scoped packages, npx handles resolution.
		name := cfg.PackageName
		// Strip scope for the binary name.
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		return name
	case PackageTypePyPI:
		// PyPI packages typically install a console_scripts entry with the package name.
		return cfg.PackageName
	case PackageTypeGit:
		// Default for git repos is index.js; use --entrypoint to override.
		return "index.js"
	default:
		return cfg.PackageName
	}
}

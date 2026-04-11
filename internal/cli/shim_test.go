package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestDetectPackageType(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want PackageType
	}{
		{"scoped npm package", "@modelcontextprotocol/server-github", PackageTypeNPM},
		{"scoped npm with version", "@modelcontextprotocol/server-github@1.2.3", PackageTypeNPM},
		{"git URL https", "https://github.com/user/repo.git", PackageTypeGit},
		{"git URL ssh", "git@github.com:user/repo.git", PackageTypeGit},
		{"gitlab URL", "https://gitlab.com/user/repo.git", PackageTypeGit},
		{"bare name defaults to pypi", "mcp-server-fetch", PackageTypePyPI},
		{"bare name with version", "mcp-server-fetch@0.6.2", PackageTypePyPI},
		{"npm unscoped with slash", "some-org/package", PackageTypeNPM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPackageType(tt.ref)
			if got != tt.want {
				t.Errorf("detectPackageType(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestSplitNPMNameVersion(t *testing.T) {
	tests := []struct {
		ref         string
		wantName    string
		wantVersion string
	}{
		{"@scope/package@1.2.3", "@scope/package", "1.2.3"},
		{"@scope/package", "@scope/package", "latest"},
		{"package@2.0.0", "package", "2.0.0"},
		{"package", "package", "latest"},
		{"@modelcontextprotocol/server-github@1.0.0", "@modelcontextprotocol/server-github", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			name, version := splitNPMNameVersion(tt.ref)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestSplitPyPINameVersion(t *testing.T) {
	tests := []struct {
		ref         string
		wantName    string
		wantVersion string
	}{
		{"mcp-server-fetch@0.6.2", "mcp-server-fetch", "0.6.2"},
		{"mcp-server-fetch==0.6.2", "mcp-server-fetch", "0.6.2"},
		{"mcp-server-fetch", "mcp-server-fetch", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			name, version := splitPyPINameVersion(tt.ref)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestParseShimRef(t *testing.T) {
	tests := []struct {
		name         string
		ref          string
		explicitType string
		wantName     string
		wantVersion  string
		wantType     PackageType
		wantErr      bool
	}{
		{
			name:     "npm prefix",
			ref:      "npm:@modelcontextprotocol/server-github@1.2.3",
			wantName: "@modelcontextprotocol/server-github", wantVersion: "1.2.3",
			wantType: PackageTypeNPM,
		},
		{
			name:     "pypi prefix",
			ref:      "pypi:mcp-server-fetch@0.6.2",
			wantName: "mcp-server-fetch", wantVersion: "0.6.2",
			wantType: PackageTypePyPI,
		},
		{
			name:     "auto-detect npm scoped",
			ref:      "@modelcontextprotocol/server-github",
			wantName: "@modelcontextprotocol/server-github", wantVersion: "latest",
			wantType: PackageTypeNPM,
		},
		{
			name:     "auto-detect pypi",
			ref:      "mcp-server-fetch",
			wantName: "mcp-server-fetch", wantVersion: "latest",
			wantType: PackageTypePyPI,
		},
		{
			name:         "explicit type overrides",
			ref:          "my-package@1.0",
			explicitType: "npm",
			wantName:     "my-package", wantVersion: "1.0",
			wantType: PackageTypeNPM,
		},
		{
			name:     "git prefix with ref",
			ref:      "git:https://github.com/user/repo.git@v1.0",
			wantName: "repo", wantVersion: "v1.0",
			wantType: PackageTypeGit,
		},
		{
			name:     "git prefix no ref",
			ref:      "git:https://github.com/user/mcp-server.git",
			wantName: "mcp-server", wantVersion: "latest",
			wantType: PackageTypeGit,
		},
		{
			name:     "auto-detect git from github URL",
			ref:      "https://github.com/user/my-tool.git@main",
			wantName: "my-tool", wantVersion: "main",
			wantType: PackageTypeGit,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
		},
		{
			name:         "invalid type flag",
			ref:          "some-package",
			explicitType: "cargo",
			wantErr:      true,
		},
		{
			name:     "pypi with == separator",
			ref:      "pypi:mcp-server-fetch==0.6.2",
			wantName: "mcp-server-fetch", wantVersion: "0.6.2",
			wantType: PackageTypePyPI,
		},
		{
			name:     "npm no version",
			ref:      "npm:express",
			wantName: "express", wantVersion: "latest",
			wantType: PackageTypeNPM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseShimRef(tt.ref, tt.explicitType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.PackageName != tt.wantName {
				t.Errorf("PackageName = %q, want %q", cfg.PackageName, tt.wantName)
			}
			if cfg.PackageVersion != tt.wantVersion {
				t.Errorf("PackageVersion = %q, want %q", cfg.PackageVersion, tt.wantVersion)
			}
			if cfg.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", cfg.Type, tt.wantType)
			}
		})
	}
}

func TestDefaultOutputTag(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"@modelcontextprotocol/server-github", "mcp-server-github:latest"},
		{"mcp-server-fetch", "mcp-server-fetch:latest"},
		{"express", "mcp-express:latest"},
		{"@scope/mcp-tools", "mcp-tools:latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultOutputTag(tt.name)
			if got != tt.want {
				t.Errorf("defaultOutputTag(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDefaultEntrypoint(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ShimConfig
		want string
	}{
		{
			name: "npm scoped package",
			cfg:  &ShimConfig{PackageName: "@modelcontextprotocol/server-github", Type: PackageTypeNPM},
			want: "server-github",
		},
		{
			name: "npm unscoped package",
			cfg:  &ShimConfig{PackageName: "express", Type: PackageTypeNPM},
			want: "express",
		},
		{
			name: "pypi package",
			cfg:  &ShimConfig{PackageName: "mcp-server-fetch", Type: PackageTypePyPI},
			want: "mcp-server-fetch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultEntrypoint(tt.cfg)
			if got != tt.want {
				t.Errorf("defaultEntrypoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateDockerfileNPM(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:    "@modelcontextprotocol/server-github",
		PackageVersion: "1.2.3",
		Type:           PackageTypeNPM,
		BaseImage:      "node:22-alpine",
	}

	df, err := generateDockerfileWithTimestamp(cfg, "2026-01-29T12:00:00Z")
	if err != nil {
		t.Fatalf("generateDockerfile() error: %v", err)
	}

	// Verify key Dockerfile content.
	checks := []string{
		"FROM node:22-alpine AS runtime",
		`LABEL org.opencontainers.image.title="@modelcontextprotocol/server-github"`,
		`LABEL org.opencontainers.image.version="1.2.3"`,
		`LABEL dev.agentcontainers.mcp.transport="stdio"`,
		`LABEL dev.agentcontainers.mcp.source-registry="npm"`,
		"npm install -g @modelcontextprotocol/server-github@1.2.3 --ignore-scripts",
		"npm cache clean --force",
		"addgroup -g 1000 mcpuser",
		"adduser -u 1000 -G mcpuser",
		"USER mcpuser",
		`ENTRYPOINT ["server-github"]`,
	}

	for _, check := range checks {
		if !strings.Contains(df, check) {
			t.Errorf("Dockerfile missing %q\nGot:\n%s", check, df)
		}
	}
}

func TestGenerateDockerfilePyPI(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:    "mcp-server-fetch",
		PackageVersion: "0.6.2",
		Type:           PackageTypePyPI,
		BaseImage:      "python:3.12-alpine",
	}

	df, err := generateDockerfileWithTimestamp(cfg, "2026-01-29T12:00:00Z")
	if err != nil {
		t.Fatalf("generateDockerfile() error: %v", err)
	}

	checks := []string{
		"FROM python:3.12-alpine AS runtime",
		`LABEL org.opencontainers.image.title="mcp-server-fetch"`,
		`LABEL org.opencontainers.image.version="0.6.2"`,
		`LABEL dev.agentcontainers.mcp.source-registry="pypi"`,
		"pip install --no-cache-dir mcp-server-fetch==0.6.2",
		"addgroup -g 1000 mcpuser",
		"USER mcpuser",
		`ENTRYPOINT ["mcp-server-fetch"]`,
	}

	for _, check := range checks {
		if !strings.Contains(df, check) {
			t.Errorf("Dockerfile missing %q\nGot:\n%s", check, df)
		}
	}
}

func TestGenerateDockerfileUnsupportedType(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:    "some-pkg",
		PackageVersion: "1.0",
		Type:           PackageType("cargo"),
		BaseImage:      "alpine:latest",
	}

	_, err := generateDockerfile(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported type, got nil")
	}
	if !strings.Contains(err.Error(), "no Dockerfile template") {
		t.Errorf("error = %q, want to contain 'no Dockerfile template'", err.Error())
	}
}

func TestShimFlagDefaults(t *testing.T) {
	cmd := newShimCmd()

	typeFlag := cmd.Flags().Lookup("type")
	if typeFlag == nil {
		t.Fatal("expected --type flag")
	}
	if typeFlag.DefValue != "" {
		t.Errorf("--type default = %q, want empty", typeFlag.DefValue)
	}
	if typeFlag.Shorthand != "t" {
		t.Errorf("--type shorthand = %q, want %q", typeFlag.Shorthand, "t")
	}

	outputFlag := cmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Fatal("expected --output flag")
	}
	if outputFlag.DefValue != "" {
		t.Errorf("--output default = %q, want empty", outputFlag.DefValue)
	}
	if outputFlag.Shorthand != "o" {
		t.Errorf("--output shorthand = %q, want %q", outputFlag.Shorthand, "o")
	}

	baseFlag := cmd.Flags().Lookup("base")
	if baseFlag == nil {
		t.Fatal("expected --base flag")
	}
	if baseFlag.DefValue != "" {
		t.Errorf("--base default = %q, want empty", baseFlag.DefValue)
	}

	dryRunFlag := cmd.Flags().Lookup("dry-run")
	if dryRunFlag == nil {
		t.Fatal("expected --dry-run flag")
	}
	if dryRunFlag.DefValue != "false" {
		t.Errorf("--dry-run default = %q, want %q", dryRunFlag.DefValue, "false")
	}
}

// mockBuilder records Build calls for verification.
type mockBuilder struct {
	mu         sync.Mutex
	calls      []mockBuildCall
	buildError error
}

type mockBuildCall struct {
	Dockerfile string
	Tag        string
}

func (m *mockBuilder) Build(_ context.Context, dockerfile string, tag string, w io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockBuildCall{Dockerfile: dockerfile, Tag: tag})
	if m.buildError != nil {
		return m.buildError
	}
	_, _ = fmt.Fprintln(w, `{"stream":"Successfully built abc123"}`)
	return nil
}

func (m *mockBuilder) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockBuilder) lastCall() mockBuildCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[len(m.calls)-1]
}

// withMockBuilder sets shimBuilder to a mock for the duration of the test and
// restores it afterward.
func withMockBuilder(t *testing.T, m *mockBuilder) {
	t.Helper()
	orig := shimBuilder
	shimBuilder = m
	t.Cleanup(func() { shimBuilder = orig })
}

func TestShimCommandDryRun(t *testing.T) {
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	tests := []struct {
		name      string
		args      []string
		wantInOut []string
	}{
		{
			name: "dry run npm prints dockerfile",
			args: []string{"shim", "--dry-run", "npm:@modelcontextprotocol/server-github@1.2.3"},
			wantInOut: []string{
				"Package:    @modelcontextprotocol/server-github@1.2.3",
				"Type:       npm",
				"Generated Dockerfile:",
				"---",
				"FROM node:22-alpine",
			},
		},
		{
			name: "dry run pypi prints dockerfile",
			args: []string{"shim", "--dry-run", "pypi:mcp-server-fetch@0.6.2"},
			wantInOut: []string{
				"Package:    mcp-server-fetch@0.6.2",
				"Type:       pypi",
				"Generated Dockerfile:",
				"pip install",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf bytes.Buffer
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetOut(&outBuf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := outBuf.String()
			for _, want := range tt.wantInOut {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot:\n%s", want, output)
				}
			}

			// Dry run should NOT call the builder.
			if mock.callCount() != 0 {
				t.Errorf("expected no Build calls in dry-run mode, got %d", mock.callCount())
			}
		})
	}
}

func TestShimCommandBuild(t *testing.T) {
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "npm:@modelcontextprotocol/server-github@1.2.3"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()

	// Should show build progress messages.
	if !strings.Contains(output, "Building image") {
		t.Errorf("output missing 'Building image'\nGot:\n%s", output)
	}
	if !strings.Contains(output, "Image built:") {
		t.Errorf("output missing 'Image built:'\nGot:\n%s", output)
	}

	// Should NOT show the dry-run Dockerfile block.
	if strings.Contains(output, "Generated Dockerfile:") {
		t.Errorf("output should not contain 'Generated Dockerfile:' in build mode\nGot:\n%s", output)
	}

	// Builder should have been called exactly once.
	if mock.callCount() != 1 {
		t.Fatalf("expected 1 Build call, got %d", mock.callCount())
	}

	call := mock.lastCall()
	if call.Tag != "mcp-server-github:latest" {
		t.Errorf("Build tag = %q, want %q", call.Tag, "mcp-server-github:latest")
	}
	if !strings.Contains(call.Dockerfile, "FROM node:22-alpine") {
		t.Errorf("Build Dockerfile missing base image\nGot:\n%s", call.Dockerfile)
	}
}

func TestShimCommandBuildError(t *testing.T) {
	mock := &mockBuilder{buildError: fmt.Errorf("daemon connection refused")}
	withMockBuilder(t, mock)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "npm:express@4.0"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from build failure, got nil")
	}
	if !strings.Contains(err.Error(), "daemon connection refused") {
		t.Errorf("error = %q, want to contain 'daemon connection refused'", err.Error())
	}
}

func TestShimCommandBuildCustomTag(t *testing.T) {
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "--output", "myrepo/myimage:v1", "npm:express@4.0"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.callCount() != 1 {
		t.Fatalf("expected 1 Build call, got %d", mock.callCount())
	}
	if mock.lastCall().Tag != "myrepo/myimage:v1" {
		t.Errorf("Build tag = %q, want %q", mock.lastCall().Tag, "myrepo/myimage:v1")
	}
}

func TestShimCommandExecution(t *testing.T) {
	// Use a mock builder so tests don't require Docker.
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantInOut  []string
		wantNotOut []string
	}{
		{
			name: "npm scoped package dry-run",
			args: []string{"shim", "--dry-run", "npm:@modelcontextprotocol/server-github@1.2.3"},
			wantInOut: []string{
				"Package:    @modelcontextprotocol/server-github@1.2.3",
				"Type:       npm",
				"Base image: node:22-alpine",
				"Generated Dockerfile:",
			},
		},
		{
			name: "pypi package dry-run",
			args: []string{"shim", "--dry-run", "pypi:mcp-server-fetch@0.6.2"},
			wantInOut: []string{
				"Package:    mcp-server-fetch@0.6.2",
				"Type:       pypi",
				"Base image: python:3.12-alpine",
			},
		},
		{
			name: "custom output tag dry-run",
			args: []string{"shim", "--dry-run", "--output", "myrepo/myimage:v1", "npm:express@4.0"},
			wantInOut: []string{
				"Output tag: myrepo/myimage:v1",
			},
		},
		{
			name: "custom base image dry-run",
			args: []string{"shim", "--dry-run", "--base", "node:20-slim", "npm:express@4.0"},
			wantInOut: []string{
				"Base image: node:20-slim",
			},
		},
		{
			name:    "no args",
			args:    []string{"shim"},
			wantErr: true,
		},
		{
			name: "git dry-run",
			args: []string{"shim", "--dry-run", "git:https://github.com/user/repo.git@v1"},
			wantInOut: []string{
				"Package:    repo@v1",
				"Type:       git",
				"Base image: node:22-alpine",
				"Generated Dockerfile:",
				"git clone",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf bytes.Buffer
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetOut(&outBuf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := outBuf.String()
			for _, want := range tt.wantInOut {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot:\n%s", want, output)
				}
			}
			for _, notWant := range tt.wantNotOut {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q\nGot:\n%s", notWant, output)
				}
			}
		})
	}
}

func TestShimHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("shim --help failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "MCP server") {
		t.Errorf("expected 'MCP server' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--type") {
		t.Errorf("expected '--type' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--output") {
		t.Errorf("expected '--output' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--base") {
		t.Errorf("expected '--base' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--dry-run") {
		t.Errorf("expected '--dry-run' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--entrypoint") {
		t.Errorf("expected '--entrypoint' in help text, got:\n%s", output)
	}
}

func TestParsePackageType(t *testing.T) {
	tests := []struct {
		input   string
		want    PackageType
		wantErr bool
	}{
		{"npm", PackageTypeNPM, false},
		{"NPM", PackageTypeNPM, false},
		{"pypi", PackageTypePyPI, false},
		{"PyPI", PackageTypePyPI, false},
		{"git", PackageTypeGit, false},
		{"cargo", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePackageType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parsePackageType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShimBaseImageDefaults(t *testing.T) {
	npmCfg, err := parseShimRef("npm:express@4.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if npmCfg.BaseImage != "node:22-alpine" {
		t.Errorf("npm BaseImage = %q, want %q", npmCfg.BaseImage, "node:22-alpine")
	}

	pypiCfg, err := parseShimRef("pypi:mcp-server@1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if pypiCfg.BaseImage != "python:3.12-alpine" {
		t.Errorf("pypi BaseImage = %q, want %q", pypiCfg.BaseImage, "python:3.12-alpine")
	}
}

func TestBuildContextTar(t *testing.T) {
	content := "FROM alpine:latest\nRUN echo hello\n"
	reader, err := buildContextTar(content)
	if err != nil {
		t.Fatalf("buildContextTar() error: %v", err)
	}

	tr := tar.NewReader(reader)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("reading tar header: %v", err)
	}
	if hdr.Name != "Dockerfile" {
		t.Errorf("tar entry name = %q, want %q", hdr.Name, "Dockerfile")
	}
	if hdr.Size != int64(len(content)) {
		t.Errorf("tar entry size = %d, want %d", hdr.Size, len(content))
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		t.Fatalf("reading tar body: %v", err)
	}
	if buf.String() != content {
		t.Errorf("tar body = %q, want %q", buf.String(), content)
	}

	// Should have exactly one entry.
	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("expected EOF after single entry, got: %v", err)
	}
}

func TestSplitGitURLRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantURL string
		wantRef string
	}{
		{
			name:    "https with .git and tag",
			ref:     "https://github.com/user/repo.git@v1.0",
			wantURL: "https://github.com/user/repo.git",
			wantRef: "v1.0",
		},
		{
			name:    "https with .git and branch",
			ref:     "https://github.com/user/repo.git@main",
			wantURL: "https://github.com/user/repo.git",
			wantRef: "main",
		},
		{
			name:    "https with .git no ref",
			ref:     "https://github.com/user/repo.git",
			wantURL: "https://github.com/user/repo.git",
			wantRef: "",
		},
		{
			name:    "ssh with .git and tag",
			ref:     "git@github.com:user/repo.git@v2.0",
			wantURL: "git@github.com:user/repo.git",
			wantRef: "v2.0",
		},
		{
			name:    "ssh with .git no ref",
			ref:     "git@github.com:user/repo.git",
			wantURL: "git@github.com:user/repo.git",
			wantRef: "",
		},
		{
			name:    "https without .git and ref",
			ref:     "https://github.com/user/repo@v1.0",
			wantURL: "https://github.com/user/repo",
			wantRef: "v1.0",
		},
		{
			name:    "https without .git no ref",
			ref:     "https://github.com/user/repo",
			wantURL: "https://github.com/user/repo",
			wantRef: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotRef := splitGitURLRef(tt.ref)
			if gotURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", gotURL, tt.wantURL)
			}
			if gotRef != tt.wantRef {
				t.Errorf("ref = %q, want %q", gotRef, tt.wantRef)
			}
		})
	}
}

func TestRepoNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/user/mcp-server.git", "mcp-server"},
		{"https://github.com/user/repo.git", "repo"},
		{"https://github.com/user/repo", "repo"},
		{"https://gitlab.com/org/my-tool.git", "my-tool"},
		{"git@github.com:user/my-repo.git", "my-repo"},
		{"simple-name", "simple-name"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := repoNameFromURL(tt.url)
			if got != tt.want {
				t.Errorf("repoNameFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestGenerateDockerfileGit(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:    "mcp-server",
		PackageVersion: "v1.0",
		Type:           PackageTypeGit,
		BaseImage:      "node:22-alpine",
		RepoURL:        "https://github.com/user/mcp-server.git",
		GitRef:         "v1.0",
	}

	df, err := generateDockerfileWithTimestamp(cfg, "2026-01-29T12:00:00Z")
	if err != nil {
		t.Fatalf("generateDockerfileWithTimestamp() error: %v", err)
	}

	checks := []string{
		"FROM node:22-alpine AS runtime",
		`LABEL org.opencontainers.image.title="mcp-server"`,
		`LABEL org.opencontainers.image.version="v1.0"`,
		`LABEL dev.agentcontainers.mcp.transport="stdio"`,
		`LABEL dev.agentcontainers.mcp.source-registry="git"`,
		`LABEL dev.agentcontainers.mcp.source-identifier="https://github.com/user/mcp-server.git@v1.0"`,
		"apk add --no-cache git",
		"addgroup -g 1000 mcpuser",
		"adduser -u 1000 -G mcpuser",
		"git clone --depth 1 --branch v1.0 https://github.com/user/mcp-server.git .",
		"npm install --production --ignore-scripts",
		"npm cache clean --force",
		"USER mcpuser",
		`ENTRYPOINT ["node", "index.js"]`,
	}

	for _, check := range checks {
		if !strings.Contains(df, check) {
			t.Errorf("Dockerfile missing %q\nGot:\n%s", check, df)
		}
	}
}

func TestGenerateDockerfileGitNoRef(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:    "mcp-server",
		PackageVersion: "latest",
		Type:           PackageTypeGit,
		BaseImage:      "node:22-alpine",
		RepoURL:        "https://github.com/user/mcp-server.git",
		GitRef:         "",
	}

	df, err := generateDockerfileWithTimestamp(cfg, "2026-01-29T12:00:00Z")
	if err != nil {
		t.Fatalf("generateDockerfileWithTimestamp() error: %v", err)
	}

	// Without a ref, clone should not include --branch.
	if strings.Contains(df, "--branch") {
		t.Errorf("Dockerfile should not contain --branch when GitRef is empty\nGot:\n%s", df)
	}
	if !strings.Contains(df, "git clone --depth 1 https://github.com/user/mcp-server.git .") {
		t.Errorf("Dockerfile missing expected clone command\nGot:\n%s", df)
	}
}

func TestGenerateDockerfileGitCustomEntrypoint(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:        "mcp-server",
		PackageVersion:     "v1.0",
		Type:               PackageTypeGit,
		BaseImage:          "node:22-alpine",
		RepoURL:            "https://github.com/user/mcp-server.git",
		GitRef:             "v1.0",
		EntrypointOverride: "src/main.js",
	}

	df, err := generateDockerfileWithTimestamp(cfg, "2026-01-29T12:00:00Z")
	if err != nil {
		t.Fatalf("generateDockerfileWithTimestamp() error: %v", err)
	}

	if !strings.Contains(df, `ENTRYPOINT ["node", "src/main.js"]`) {
		t.Errorf("Dockerfile should use custom entrypoint\nGot:\n%s", df)
	}
}

func TestDefaultEntrypointGit(t *testing.T) {
	cfg := &ShimConfig{PackageName: "my-server", Type: PackageTypeGit}
	got := defaultEntrypoint(cfg)
	if got != "index.js" {
		t.Errorf("defaultEntrypoint(git) = %q, want %q", got, "index.js")
	}
}

func TestDefaultEntrypointOverride(t *testing.T) {
	cfg := &ShimConfig{
		PackageName:        "my-server",
		Type:               PackageTypeNPM,
		EntrypointOverride: "custom-binary",
	}
	got := defaultEntrypoint(cfg)
	if got != "custom-binary" {
		t.Errorf("defaultEntrypoint(override) = %q, want %q", got, "custom-binary")
	}
}

func TestShimBaseImageDefaultGit(t *testing.T) {
	cfg, err := parseShimRef("git:https://github.com/user/repo.git@v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseImage != "node:22-alpine" {
		t.Errorf("git BaseImage = %q, want %q", cfg.BaseImage, "node:22-alpine")
	}
}

func TestShimGitBuild(t *testing.T) {
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "git:https://github.com/user/mcp-server.git@v1.0"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Building image") {
		t.Errorf("output missing 'Building image'\nGot:\n%s", output)
	}
	if !strings.Contains(output, "Image built:") {
		t.Errorf("output missing 'Image built:'\nGot:\n%s", output)
	}

	if mock.callCount() != 1 {
		t.Fatalf("expected 1 Build call, got %d", mock.callCount())
	}

	call := mock.lastCall()
	if call.Tag != "mcp-server:latest" {
		t.Errorf("Build tag = %q, want %q", call.Tag, "mcp-server:latest")
	}
	if !strings.Contains(call.Dockerfile, "git clone") {
		t.Errorf("Build Dockerfile missing git clone\nGot:\n%s", call.Dockerfile)
	}
}

func TestShimEntrypointFlag(t *testing.T) {
	cmd := newShimCmd()

	epFlag := cmd.Flags().Lookup("entrypoint")
	if epFlag == nil {
		t.Fatal("expected --entrypoint flag")
	}
	if epFlag.DefValue != "" {
		t.Errorf("--entrypoint default = %q, want empty", epFlag.DefValue)
	}
}

func TestShimCommandGitWithEntrypoint(t *testing.T) {
	mock := &mockBuilder{}
	withMockBuilder(t, mock)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"shim", "--dry-run", "--entrypoint", "src/server.js", "git:https://github.com/user/repo.git@v1"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, `ENTRYPOINT ["node", "src/server.js"]`) {
		t.Errorf("output should contain custom entrypoint\nGot:\n%s", output)
	}
}

func TestDetectPackageTypeGitPatterns(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want PackageType
	}{
		{"github without .git", "https://github.com/user/repo", PackageTypeGit},
		{"gitlab without .git", "https://gitlab.com/user/repo", PackageTypeGit},
		{"bitbucket", "https://bitbucket.org/user/repo.git", PackageTypeGit},
		{"github with ref", "https://github.com/user/repo.git@v1.0", PackageTypeGit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPackageType(tt.ref)
			if got != tt.want {
				t.Errorf("detectPackageType(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestImageBuilderInterface(t *testing.T) {
	// Verify that dockerImageBuilder satisfies the ImageBuilder interface.
	var _ ImageBuilder = (*dockerImageBuilder)(nil)
}

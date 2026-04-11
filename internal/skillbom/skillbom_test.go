package skillbom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Metadata parsing tests ---

func TestParseFrontmatter_Full(t *testing.T) {
	content := `---
name: code-review
version: 1.2.0
description: Review code changes
requires:
  - filesystem.read
  - git.diff
  - git.log
---

# Code Review
`
	meta, err := parseFrontmatter(content)
	if err != nil {
		t.Fatalf("parseFrontmatter() error = %v", err)
	}
	if meta.Name != "code-review" {
		t.Errorf("Name = %q, want %q", meta.Name, "code-review")
	}
	if meta.Version != "1.2.0" {
		t.Errorf("Version = %q, want %q", meta.Version, "1.2.0")
	}
	if meta.Description != "Review code changes" {
		t.Errorf("Description = %q, want %q", meta.Description, "Review code changes")
	}
	if len(meta.Capabilities) != 3 {
		t.Fatalf("Capabilities len = %d, want 3", len(meta.Capabilities))
	}
	wantCaps := []string{"filesystem.read", "git.diff", "git.log"}
	for i, c := range wantCaps {
		if meta.Capabilities[i] != c {
			t.Errorf("Capabilities[%d] = %q, want %q", i, meta.Capabilities[i], c)
		}
	}
}

func TestParseFrontmatter_None(t *testing.T) {
	content := "# No frontmatter here\nJust a regular markdown file."
	meta, err := parseFrontmatter(content)
	if err != nil {
		t.Fatalf("parseFrontmatter() error = %v", err)
	}
	if meta.Name != "" {
		t.Errorf("Name = %q, want empty", meta.Name)
	}
}

func TestParseFrontmatter_Unclosed(t *testing.T) {
	content := "---\nname: broken\n"
	meta, err := parseFrontmatter(content)
	if err != nil {
		t.Fatalf("parseFrontmatter() error = %v", err)
	}
	// Unclosed frontmatter treated as no frontmatter.
	if meta.Name != "" {
		t.Errorf("Name = %q, want empty for unclosed frontmatter", meta.Name)
	}
}

func TestParseSkillDir_WithFrontmatter(t *testing.T) {
	dir := filepath.Join("testdata", "code-review")
	meta, err := ParseSkillDir(dir)
	if err != nil {
		t.Fatalf("ParseSkillDir() error = %v", err)
	}
	if meta.Name != "code-review" {
		t.Errorf("Name = %q, want %q", meta.Name, "code-review")
	}
	if len(meta.Capabilities) != 3 {
		t.Errorf("Capabilities len = %d, want 3", len(meta.Capabilities))
	}
}

func TestParseSkillDir_CapabilitiesJSON(t *testing.T) {
	dir := filepath.Join("testdata", "caps-json")
	meta, err := ParseSkillDir(dir)
	if err != nil {
		t.Fatalf("ParseSkillDir() error = %v", err)
	}
	if len(meta.Capabilities) != 2 {
		t.Fatalf("Capabilities len = %d, want 2", len(meta.Capabilities))
	}
	// Sorted order.
	if meta.Capabilities[0] != "filesystem.read" {
		t.Errorf("Capabilities[0] = %q, want %q", meta.Capabilities[0], "filesystem.read")
	}
	if meta.Capabilities[1] != "network.egress" {
		t.Errorf("Capabilities[1] = %q, want %q", meta.Capabilities[1], "network.egress")
	}
}

func TestParseSkillDir_NoFrontmatter(t *testing.T) {
	dir := filepath.Join("testdata", "no-frontmatter")
	meta, err := ParseSkillDir(dir)
	if err != nil {
		t.Fatalf("ParseSkillDir() error = %v", err)
	}
	if meta.Name != "" {
		t.Errorf("Name = %q, want empty", meta.Name)
	}
	if len(meta.Capabilities) != 0 {
		t.Errorf("Capabilities len = %d, want 0", len(meta.Capabilities))
	}
}

func TestParseSkillDir_Missing(t *testing.T) {
	_, err := ParseSkillDir("/nonexistent/path")
	if err == nil {
		t.Fatal("ParseSkillDir() expected error for missing directory")
	}
}

// --- Normalization tests ---

func TestNormalizeText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"trim spaces", "  hello  ", "hello"},
		{"collapse whitespace", "hello   world\t\tfoo", "hello world foo"},
		{"newlines to space", "hello\n\nworld", "hello world"},
		{"empty string", "", ""},
		{"unicode NFC", "caf\u0065\u0301", "caf\u00e9"}, // e + combining acute -> precomposed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeText(tt.input)
			if got != tt.want {
				t.Errorf("normalizeText(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Content hash tests ---

func TestComputeContentHash_Deterministic(t *testing.T) {
	meta := &SkillMetadata{
		Name:         "test-skill",
		Description:  "A test skill",
		Capabilities: []string{"filesystem.read", "git.diff"},
	}

	h1, err := computeContentHash(meta)
	if err != nil {
		t.Fatalf("computeContentHash() error = %v", err)
	}
	h2, err := computeContentHash(meta)
	if err != nil {
		t.Fatalf("computeContentHash() error = %v", err)
	}
	if h1 != h2 {
		t.Errorf("Content hash not deterministic: %q != %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("Content hash should have sha256: prefix, got %q", h1)
	}
}

func TestComputeContentHash_DifferentInput(t *testing.T) {
	meta1 := &SkillMetadata{Name: "skill-a", Description: "First"}
	meta2 := &SkillMetadata{Name: "skill-b", Description: "Second"}

	h1, _ := computeContentHash(meta1)
	h2, _ := computeContentHash(meta2)
	if h1 == h2 {
		t.Error("Different skills should produce different content hashes")
	}
}

func TestComputeContentHash_CapabilityOrder(t *testing.T) {
	meta1 := &SkillMetadata{
		Name:         "test",
		Capabilities: []string{"git.diff", "filesystem.read"},
	}
	meta2 := &SkillMetadata{
		Name:         "test",
		Capabilities: []string{"filesystem.read", "git.diff"},
	}

	h1, _ := computeContentHash(meta1)
	h2, _ := computeContentHash(meta2)
	if h1 != h2 {
		t.Error("Capability order should not affect content hash")
	}
}

// --- Generator tests ---

func TestGenerator_Generate(t *testing.T) {
	gen := NewGenerator("0.1.0-test")
	bom, err := gen.Generate(context.Background(), filepath.Join("testdata", "code-review"))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if bom.Format != Format {
		t.Errorf("Format = %q, want %q", bom.Format, Format)
	}
	if bom.SkillName != "code-review" {
		t.Errorf("SkillName = %q, want %q", bom.SkillName, "code-review")
	}
	if bom.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", bom.Version, "1.0.0")
	}
	if bom.Description != "Automated code review assistant" {
		t.Errorf("Description = %q, want %q", bom.Description, "Automated code review assistant")
	}
	if len(bom.Capabilities) != 3 {
		t.Errorf("Capabilities len = %d, want 3", len(bom.Capabilities))
	}
	if bom.ContentHash == "" {
		t.Error("ContentHash should not be empty")
	}
	if !strings.HasPrefix(bom.ContentHash, "sha256:") {
		t.Errorf("ContentHash should have sha256: prefix, got %q", bom.ContentHash)
	}
	if bom.Digest == "" {
		t.Error("Digest should not be empty")
	}
	if !strings.HasPrefix(bom.Digest, "sha256:") {
		t.Errorf("Digest should have sha256: prefix, got %q", bom.Digest)
	}
	if bom.Components < 2 {
		t.Errorf("Components = %d, want at least 2 (SKILL.md + script)", bom.Components)
	}
	if bom.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}

	// Verify Content is valid CycloneDX JSON.
	var doc CDXDocument
	if err := json.Unmarshal(bom.Content, &doc); err != nil {
		t.Fatalf("Content is not valid JSON: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", doc.BOMFormat, "CycloneDX")
	}
	if doc.SpecVersion != "1.7" {
		t.Errorf("SpecVersion = %q, want %q", doc.SpecVersion, "1.7")
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Errorf("SerialNumber = %q, want urn:uuid: prefix", doc.SerialNumber)
	}
}

func TestGenerator_Generate_NameFallback(t *testing.T) {
	gen := NewGenerator("0.1.0")
	bom, err := gen.Generate(context.Background(), filepath.Join("testdata", "no-frontmatter"))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// Should fall back to directory name.
	if bom.SkillName != "no-frontmatter" {
		t.Errorf("SkillName = %q, want %q (directory name fallback)", bom.SkillName, "no-frontmatter")
	}
}

func TestGenerator_Generate_MissingSKILLmd(t *testing.T) {
	gen := NewGenerator("0.1.0")
	_, err := gen.Generate(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("Generate() expected error for directory without SKILL.md")
	}
}

// --- CycloneDX output tests ---

func TestBuildCycloneDX_Structure(t *testing.T) {
	meta := &SkillMetadata{
		Name:         "test-skill",
		Version:      "1.0.0",
		Description:  "A test",
		Capabilities: []string{"filesystem.read"},
	}
	files := []fileEntry{
		{RelPath: "SKILL.md", SHA256: "aabbccdd", Executable: false},
		{RelPath: "scripts/run.sh", SHA256: "eeff0011", Executable: true},
	}

	data, err := buildCycloneDX(meta, files, "sha256:contenthash", "0.1.0")
	if err != nil {
		t.Fatalf("buildCycloneDX() error = %v", err)
	}

	var doc CDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}

	// Check metadata.
	if doc.Metadata.Component.Name != "test-skill" {
		t.Errorf("metadata.component.name = %q, want %q", doc.Metadata.Component.Name, "test-skill")
	}
	if doc.Metadata.Tools == nil || len(doc.Metadata.Tools.Components) != 1 {
		t.Fatal("metadata.tools should have 1 component")
	}
	if doc.Metadata.Tools.Components[0].Version != "0.1.0" {
		t.Errorf("tool version = %q, want %q", doc.Metadata.Tools.Components[0].Version, "0.1.0")
	}

	// Check components.
	if len(doc.Components) != 2 {
		t.Fatalf("components len = %d, want 2", len(doc.Components))
	}

	// SKILL.md component should have embedding hash property.
	skillComp := doc.Components[0]
	if skillComp.BOMRef != "SKILL.md" {
		t.Errorf("components[0].bom-ref = %q, want %q", skillComp.BOMRef, "SKILL.md")
	}
	foundEmbedHash := false
	for _, p := range skillComp.Properties {
		if p.Name == "agentcontainers:semantic-embedding-hash" && p.Value == "sha256:contenthash" {
			foundEmbedHash = true
		}
	}
	if !foundEmbedHash {
		t.Error("SKILL.md component missing agentcontainers:semantic-embedding-hash property")
	}

	// Script component should have executable property.
	scriptComp := doc.Components[1]
	foundExec := false
	for _, p := range scriptComp.Properties {
		if p.Name == "agentcontainers:executable" && p.Value == "true" {
			foundExec = true
		}
	}
	if !foundExec {
		t.Error("script component missing agentcontainers:executable property")
	}

	// Check top-level properties.
	foundCaps := false
	for _, p := range doc.Properties {
		if p.Name == "agentcontainers:required-capabilities" {
			foundCaps = true
			if !strings.Contains(p.Value, "filesystem.read") {
				t.Errorf("capabilities property missing filesystem.read: %q", p.Value)
			}
		}
	}
	if !foundCaps {
		t.Error("missing agentcontainers:required-capabilities top-level property")
	}

	// Check dependencies.
	if len(doc.Dependencies) != 1 {
		t.Fatalf("dependencies len = %d, want 1", len(doc.Dependencies))
	}
	if doc.Dependencies[0].Ref != "test-skill" {
		t.Errorf("dependency ref = %q, want %q", doc.Dependencies[0].Ref, "test-skill")
	}
	if len(doc.Dependencies[0].DependsOn) != 2 {
		t.Errorf("dependsOn len = %d, want 2", len(doc.Dependencies[0].DependsOn))
	}
}

func TestBuildCycloneDX_NoCaps(t *testing.T) {
	meta := &SkillMetadata{Name: "minimal", Version: "0.1.0"}
	files := []fileEntry{{RelPath: "SKILL.md", SHA256: "abc"}}

	data, err := buildCycloneDX(meta, files, "sha256:hash", "")
	if err != nil {
		t.Fatalf("buildCycloneDX() error = %v", err)
	}

	var doc CDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}

	// Should have no top-level properties when no capabilities.
	for _, p := range doc.Properties {
		if p.Name == "agentcontainers:required-capabilities" {
			t.Error("should not have required-capabilities property when no capabilities declared")
		}
	}

	// Should have no tools when acVersion is empty.
	if doc.Metadata.Tools != nil {
		t.Error("should not have tools when acVersion is empty")
	}
}

// --- Drift detection tests ---

func TestComputeDrift_Identical(t *testing.T) {
	a := &SkillBOM{ContentHash: "sha256:abc", Capabilities: []string{"filesystem.read"}}
	b := &SkillBOM{ContentHash: "sha256:abc", Capabilities: []string{"filesystem.read"}}

	result := ComputeDrift(a, b)
	if result.Distance != 0.0 {
		t.Errorf("Distance = %f, want 0.0", result.Distance)
	}
	if result.Classification != DriftPatch {
		t.Errorf("Classification = %q, want %q", result.Classification, DriftPatch)
	}
	if result.CapabilityEscalation {
		t.Error("CapabilityEscalation should be false for identical capabilities")
	}
}

func TestComputeDrift_Different(t *testing.T) {
	a := &SkillBOM{ContentHash: "sha256:abc", Capabilities: []string{"filesystem.read"}}
	b := &SkillBOM{ContentHash: "sha256:xyz", Capabilities: []string{"filesystem.read"}}

	result := ComputeDrift(a, b)
	if result.Distance != 1.0 {
		t.Errorf("Distance = %f, want 1.0", result.Distance)
	}
	if result.Classification != DriftBreaking {
		t.Errorf("Classification = %q, want %q", result.Classification, DriftBreaking)
	}
}

func TestComputeDrift_CapabilityEscalation(t *testing.T) {
	a := &SkillBOM{
		ContentHash:  "sha256:abc",
		Capabilities: []string{"filesystem.read"},
	}
	b := &SkillBOM{
		ContentHash:  "sha256:abc",
		Capabilities: []string{"filesystem.read", "network.egress"},
	}

	result := ComputeDrift(a, b)
	if !result.CapabilityEscalation {
		t.Error("CapabilityEscalation should be true")
	}
	if len(result.NewCapabilities) != 1 || result.NewCapabilities[0] != "network.egress" {
		t.Errorf("NewCapabilities = %v, want [network.egress]", result.NewCapabilities)
	}
}

func TestComputeDrift_CapabilityRemoval(t *testing.T) {
	a := &SkillBOM{
		ContentHash:  "sha256:abc",
		Capabilities: []string{"filesystem.read", "network.egress"},
	}
	b := &SkillBOM{
		ContentHash:  "sha256:abc",
		Capabilities: []string{"filesystem.read"},
	}

	result := ComputeDrift(a, b)
	if result.CapabilityEscalation {
		t.Error("CapabilityEscalation should be false for capability removal")
	}
}

func TestClassifyDrift_Boundaries(t *testing.T) {
	tests := []struct {
		distance float64
		want     DriftClassification
	}{
		{0.00, DriftPatch},
		{0.04, DriftPatch},
		{0.05, DriftMinor},
		{0.14, DriftMinor},
		{0.15, DriftMajor},
		{0.39, DriftMajor},
		{0.40, DriftBreaking},
		{0.41, DriftBreaking},
		{1.00, DriftBreaking},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := classifyDrift(tt.distance, DefaultThresholds)
			if got != tt.want {
				t.Errorf("classifyDrift(%f) = %q, want %q", tt.distance, got, tt.want)
			}
		})
	}
}

func TestComputeDriftWithThresholds_Custom(t *testing.T) {
	custom := DriftThresholds{
		Patch:    0.10,
		Minor:    0.30,
		Major:    0.60,
		Breaking: 0.60,
	}

	a := &SkillBOM{ContentHash: "sha256:abc"}
	b := &SkillBOM{ContentHash: "sha256:abc"}

	result := ComputeDriftWithThresholds(a, b, custom)
	// Distance 0.0, custom patch threshold is 0.10, so still patch.
	if result.Classification != DriftPatch {
		t.Errorf("Classification = %q, want %q", result.Classification, DriftPatch)
	}
}

func TestIsDriftAcceptable(t *testing.T) {
	if !IsDriftAcceptable(0.04, 0.05) {
		t.Error("0.04 should be acceptable with threshold 0.05")
	}
	if IsDriftAcceptable(0.05, 0.05) {
		t.Error("0.05 should not be acceptable with threshold 0.05")
	}
	if IsDriftAcceptable(0.50, 0.40) {
		t.Error("0.50 should not be acceptable with threshold 0.40")
	}
}

// --- File enumeration tests ---

func TestEnumerateFiles(t *testing.T) {
	dir := filepath.Join("testdata", "code-review")
	files, err := enumerateFiles(dir)
	if err != nil {
		t.Fatalf("enumerateFiles() error = %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected at least 2 files, got %d", len(files))
	}

	// Files should be sorted.
	for i := 1; i < len(files); i++ {
		if files[i].RelPath < files[i-1].RelPath {
			t.Errorf("files not sorted: %q < %q", files[i].RelPath, files[i-1].RelPath)
		}
	}

	// Check SKILL.md is present.
	found := false
	for _, f := range files {
		if f.RelPath == "SKILL.md" {
			found = true
			if f.SHA256 == "" {
				t.Error("SKILL.md should have a non-empty hash")
			}
		}
	}
	if !found {
		t.Error("SKILL.md not found in enumerated files")
	}
}

func TestEnumerateFiles_SkipsHidden(t *testing.T) {
	dir := t.TempDir()
	// Create a visible file and a hidden file.
	_ = os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("hello"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref"), 0o644)

	files, err := enumerateFiles(dir)
	if err != nil {
		t.Fatalf("enumerateFiles() error = %v", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.RelPath, ".") {
			t.Errorf("hidden file should be skipped: %q", f.RelPath)
		}
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

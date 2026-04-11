package skillbom

import (
	"math"
	"testing"
)

func TestCosineDistance_IdenticalVectors(t *testing.T) {
	a := []float32{1, 2, 3, 4, 5}
	got := CosineDistance(a, a)
	if math.Abs(got) > 1e-9 {
		t.Errorf("CosineDistance(a, a) = %f, want 0.0", got)
	}
}

func TestCosineDistance_OrthogonalVectors(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{0, 1, 0}
	got := CosineDistance(a, b)
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("CosineDistance(orthogonal) = %f, want 1.0", got)
	}
}

func TestCosineDistance_OppositeVectors(t *testing.T) {
	a := []float32{1, 2, 3}
	b := []float32{-1, -2, -3}
	got := CosineDistance(a, b)
	if math.Abs(got-2.0) > 1e-9 {
		t.Errorf("CosineDistance(opposite) = %f, want 2.0", got)
	}
}

func TestCosineDistance_ZeroVector(t *testing.T) {
	zero := []float32{0, 0, 0}
	nonzero := []float32{1, 2, 3}

	tests := []struct {
		name string
		a, b []float32
	}{
		{"both zero", zero, zero},
		{"a zero", zero, nonzero},
		{"b zero", nonzero, zero},
		{"a empty", nil, nonzero},
		{"b empty", nonzero, nil},
		{"both empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CosineDistance(tt.a, tt.b)
			if got != 1.0 {
				t.Errorf("CosineDistance(%v, %v) = %f, want 1.0", tt.a, tt.b, got)
			}
		})
	}
}

func TestCosineDistance_KnownValues(t *testing.T) {
	// Hand-computed: a=(3,4), b=(4,3)
	// dot=12+12=24, |a|=5, |b|=5, cos=24/25=0.96, distance=0.04
	a := []float32{3, 4}
	b := []float32{4, 3}
	got := CosineDistance(a, b)
	want := 1.0 - 24.0/25.0
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("CosineDistance([3,4],[4,3]) = %f, want %f", got, want)
	}
}

func TestCosineDistance_MismatchedLength(t *testing.T) {
	// Shorter vector is padded with implicit zeros for norm calculation.
	a := []float32{1, 0}
	b := []float32{1, 0, 0, 0}
	got := CosineDistance(a, b)
	// Both point in the same direction (extra dims are zero), should be 0.
	if math.Abs(got) > 1e-9 {
		t.Errorf("CosineDistance mismatched same-direction = %f, want 0.0", got)
	}
}

func TestNormalizeEmbedding(t *testing.T) {
	v := []float32{3, 4}
	norm := NormalizeEmbedding(v)
	if norm == nil {
		t.Fatal("NormalizeEmbedding returned nil for non-zero vector")
	}
	if len(norm) != 2 {
		t.Fatalf("NormalizeEmbedding length = %d, want 2", len(norm))
	}
	// Expected: (0.6, 0.8)
	if math.Abs(float64(norm[0])-0.6) > 1e-6 {
		t.Errorf("norm[0] = %f, want 0.6", norm[0])
	}
	if math.Abs(float64(norm[1])-0.8) > 1e-6 {
		t.Errorf("norm[1] = %f, want 0.8", norm[1])
	}
	// Verify unit length.
	var sumSq float64
	for _, x := range norm {
		sumSq += float64(x) * float64(x)
	}
	if math.Abs(sumSq-1.0) > 1e-6 {
		t.Errorf("normalized vector magnitude = %f, want 1.0", math.Sqrt(sumSq))
	}
}

func TestNormalizeEmbedding_ZeroVector(t *testing.T) {
	v := []float32{0, 0, 0}
	norm := NormalizeEmbedding(v)
	if norm != nil {
		t.Errorf("NormalizeEmbedding(zero) = %v, want nil", norm)
	}
}

func TestComputeDrift_WithEmbeddings(t *testing.T) {
	old := &SkillBOM{
		ContentHash:     "sha256:aaa",
		EmbeddingVector: []float32{1, 0, 0},
		EmbeddingModel:  "nomic-embed-text-v1.5",
		Capabilities:    []string{"filesystem.read"},
	}
	new := &SkillBOM{
		ContentHash:     "sha256:bbb",
		EmbeddingVector: []float32{0, 1, 0},
		EmbeddingModel:  "nomic-embed-text-v1.5",
		Capabilities:    []string{"filesystem.read"},
	}

	result := ComputeDrift(old, new)

	// Should use cosine distance (orthogonal = 1.0), not binary hash (which would also be 1.0).
	if !result.EmbeddingUsed {
		t.Error("EmbeddingUsed should be true when both BOMs have embeddings")
	}
	if math.Abs(result.Distance-1.0) > 1e-9 {
		t.Errorf("Distance = %f, want 1.0 (orthogonal)", result.Distance)
	}
	if result.Classification != DriftBreaking {
		t.Errorf("Classification = %q, want %q", result.Classification, DriftBreaking)
	}
}

func TestComputeDrift_WithEmbeddings_Similar(t *testing.T) {
	// Nearly identical vectors should produce small distance.
	old := &SkillBOM{
		ContentHash:     "sha256:aaa",
		EmbeddingVector: []float32{1, 0, 0},
		EmbeddingModel:  "nomic-embed-text-v1.5",
		Capabilities:    []string{"filesystem.read"},
	}
	new := &SkillBOM{
		ContentHash:     "sha256:bbb", // Hash differs but embeddings are close.
		EmbeddingVector: []float32{0.99, 0.01, 0},
		EmbeddingModel:  "nomic-embed-text-v1.5",
		Capabilities:    []string{"filesystem.read"},
	}

	result := ComputeDrift(old, new)
	if !result.EmbeddingUsed {
		t.Error("EmbeddingUsed should be true")
	}
	// Distance should be small (patch-level).
	if result.Distance >= 0.05 {
		t.Errorf("Distance = %f, want < 0.05 for similar vectors", result.Distance)
	}
	if result.Classification != DriftPatch {
		t.Errorf("Classification = %q, want %q", result.Classification, DriftPatch)
	}
}

func TestComputeDrift_WithoutEmbeddings(t *testing.T) {
	// No embeddings: falls back to content hash comparison.
	old := &SkillBOM{
		ContentHash:  "sha256:aaa",
		Capabilities: []string{"filesystem.read"},
	}
	new := &SkillBOM{
		ContentHash:  "sha256:bbb",
		Capabilities: []string{"filesystem.read"},
	}

	result := ComputeDrift(old, new)
	if result.EmbeddingUsed {
		t.Error("EmbeddingUsed should be false when no embeddings present")
	}
	if result.Distance != 1.0 {
		t.Errorf("Distance = %f, want 1.0 (binary hash mismatch)", result.Distance)
	}
}

func TestComputeDrift_PartialEmbeddings(t *testing.T) {
	// Only one BOM has embeddings: falls back to content hash.
	old := &SkillBOM{
		ContentHash:     "sha256:aaa",
		EmbeddingVector: []float32{1, 0, 0},
		Capabilities:    []string{"filesystem.read"},
	}
	new := &SkillBOM{
		ContentHash:  "sha256:bbb",
		Capabilities: []string{"filesystem.read"},
	}

	result := ComputeDrift(old, new)
	if result.EmbeddingUsed {
		t.Error("EmbeddingUsed should be false when only one BOM has embeddings")
	}
	if result.Distance != 1.0 {
		t.Errorf("Distance = %f, want 1.0 (hash fallback)", result.Distance)
	}
}

func TestComputeDrift_CapabilityEscalationWithEmbeddings(t *testing.T) {
	old := &SkillBOM{
		ContentHash:     "sha256:aaa",
		EmbeddingVector: []float32{1, 0, 0},
		Capabilities:    []string{"filesystem.read"},
	}
	new := &SkillBOM{
		ContentHash:     "sha256:aaa",
		EmbeddingVector: []float32{1, 0, 0},
		Capabilities:    []string{"filesystem.read", "network.egress"},
	}

	result := ComputeDrift(old, new)
	if !result.CapabilityEscalation {
		t.Error("CapabilityEscalation should be true")
	}
	if len(result.NewCapabilities) != 1 || result.NewCapabilities[0] != "network.egress" {
		t.Errorf("NewCapabilities = %v, want [network.egress]", result.NewCapabilities)
	}
	// Even with identical embeddings and hash, capability escalation is detected.
	if result.Distance != 0.0 {
		t.Errorf("Distance = %f, want 0.0 for identical embeddings", result.Distance)
	}
}

func TestDriftThresholds_Classification(t *testing.T) {
	tests := []struct {
		distance float64
		want     DriftClassification
	}{
		{0.00, DriftPatch},
		{0.01, DriftPatch},
		{0.049, DriftPatch},
		{0.05, DriftMinor},
		{0.10, DriftMinor},
		{0.149, DriftMinor},
		{0.15, DriftMajor},
		{0.25, DriftMajor},
		{0.399, DriftMajor},
		{0.40, DriftBreaking},
		{0.50, DriftBreaking},
		{1.00, DriftBreaking},
		{1.50, DriftBreaking},
		{2.00, DriftBreaking},
	}

	for _, tt := range tests {
		got := classifyDrift(tt.distance, DefaultThresholds)
		if got != tt.want {
			t.Errorf("classifyDrift(%f) = %q, want %q", tt.distance, got, tt.want)
		}
	}
}

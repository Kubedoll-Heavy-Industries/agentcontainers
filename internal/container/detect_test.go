package container

import (
	"testing"
)

func TestDetectRuntimeType(t *testing.T) {
	tests := []struct {
		name   string
		prober SandboxProber
		want   RuntimeType
	}{
		{
			name:   "sandbox available",
			prober: func() bool { return true },
			want:   RuntimeSandbox,
		},
		{
			name:   "sandbox unavailable falls back to docker",
			prober: func() bool { return false },
			want:   RuntimeDocker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectRuntime(tt.prober)
			if got != tt.want {
				t.Errorf("DetectRuntime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectRuntimeTypeNilProber(t *testing.T) {
	// With nil prober, should default to docker
	got := DetectRuntime(nil)
	if got != RuntimeDocker {
		t.Errorf("DetectRuntime(nil) = %q, want %q", got, RuntimeDocker)
	}
}

package enforcement

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelGRPC, "grpc"},
		{LevelNone, "none"},
		{Level(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.String())
		})
	}
}

func TestNewStrategy_ReturnsCorrectTypes(t *testing.T) {
	tests := []struct {
		name  string
		level Level
		want  any
	}{
		{"grpc returns GRPCStrategy", LevelGRPC, &GRPCStrategy{}},
		{"none returns FailClosedStrategy", LevelNone, &FailClosedStrategy{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStrategy(tt.level)
			assert.IsType(t, tt.want, s)
			assert.Equal(t, tt.level, s.Level())
			// Clean up gRPC connection if applicable
			if grpc, ok := s.(*GRPCStrategy); ok {
				_ = grpc.Close()
			}
		})
	}
}

func TestDetectLevel_ReturnsValidLevel(t *testing.T) {
	level := DetectLevel()
	// Without an enforcer sidecar running, we expect LevelNone.
	assert.True(t, level >= LevelGRPC && level <= LevelNone,
		"level %d should be between %d and %d", level, LevelGRPC, LevelNone)
}

func TestLevelGRPC_String(t *testing.T) {
	assert.Equal(t, "grpc", LevelGRPC.String())
}

func TestLevelGRPC_IsHighestPriority(t *testing.T) {
	// LevelGRPC should be the lowest numeric value (highest priority)
	assert.True(t, LevelGRPC < LevelNone,
		"LevelGRPC (%d) should be < LevelNone (%d)", LevelGRPC, LevelNone)
}

func TestDetectLevel_GRPCFromEnv(t *testing.T) {
	t.Run("no env var falls through to none", func(t *testing.T) {
		t.Setenv("AC_ENFORCER_ADDR", "")
		_ = os.Unsetenv("AC_ENFORCER_ADDR")
		level := DetectLevel()
		// Should not be grpc since no env var is set
		assert.NotEqual(t, LevelGRPC, level)
	})

	t.Run("env var set but no server falls through", func(t *testing.T) {
		t.Setenv("AC_ENFORCER_ADDR", "localhost:9999")
		level := DetectLevel()
		// Should not be grpc since health check will fail
		assert.NotEqual(t, LevelGRPC, level)
	})
}

func TestNewStrategy_GRPC_CreatesStrategy(t *testing.T) {
	// NewGRPCStrategy uses lazy connection, so it succeeds even if server isn't running.
	// Connection errors will surface during Apply/Update/Remove calls.
	t.Setenv("AC_ENFORCER_ADDR", "localhost:50051")
	s := NewStrategy(LevelGRPC)
	assert.IsType(t, &GRPCStrategy{}, s)
	assert.Equal(t, LevelGRPC, s.Level())
	if grpc, ok := s.(*GRPCStrategy); ok {
		_ = grpc.Close()
	}
}

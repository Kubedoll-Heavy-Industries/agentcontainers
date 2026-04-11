package enforcement

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

func TestFailClosedStrategy_Apply(t *testing.T) {
	s := &FailClosedStrategy{}
	err := s.Apply(context.Background(), "test", 0, &policy.ContainerPolicy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no enforcement mechanism available")
	assert.Contains(t, err.Error(), "fail-closed")
}

func TestFailClosedStrategy_Update(t *testing.T) {
	s := &FailClosedStrategy{}
	err := s.Update(context.Background(), "test", &policy.ContainerPolicy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail-closed")
}

func TestFailClosedStrategy_Remove(t *testing.T) {
	s := &FailClosedStrategy{}
	err := s.Remove(context.Background(), "test")
	require.NoError(t, err)
}

func TestFailClosedStrategy_InjectSecrets(t *testing.T) {
	s := &FailClosedStrategy{}
	err := s.InjectSecrets(context.Background(), "test", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestFailClosedStrategy_Events(t *testing.T) {
	s := &FailClosedStrategy{}
	assert.Nil(t, s.Events("any"))
}

func TestFailClosedStrategy_Level(t *testing.T) {
	s := &FailClosedStrategy{}
	assert.Equal(t, LevelNone, s.Level())
}

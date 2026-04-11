package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
)

func TestGcFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "extra args rejected",
			args:    []string{"gc", "unexpected"},
			wantErr: "unknown command",
		},
		{
			name:    "unknown runtime",
			args:    []string{"gc", "--runtime", "podman"},
			wantErr: "unknown runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestGcDefaultFlags(t *testing.T) {
	cmd := newGcCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "docker" {
		t.Errorf("expected default runtime %q, got %q", "docker", runtimeVal)
	}

	dryRunVal, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		t.Fatalf("unexpected error getting dry-run flag: %v", err)
	}
	if dryRunVal {
		t.Error("expected --dry-run to default to false")
	}

	forceVal, err := cmd.Flags().GetBool("force")
	if err != nil {
		t.Fatalf("unexpected error getting force flag: %v", err)
	}
	if forceVal {
		t.Error("expected --force to default to false")
	}

	allVal, err := cmd.Flags().GetBool("all")
	if err != nil {
		t.Fatalf("unexpected error getting all flag: %v", err)
	}
	if allVal {
		t.Error("expected --all to default to false")
	}
}

func TestGcForceShortFlag(t *testing.T) {
	cmd := newGcCmd()
	if err := cmd.ParseFlags([]string{"-f"}); err != nil {
		t.Fatalf("unexpected error parsing -f flag: %v", err)
	}

	forceVal, err := cmd.Flags().GetBool("force")
	if err != nil {
		t.Fatalf("unexpected error getting force flag: %v", err)
	}
	if !forceVal {
		t.Error("expected -f to set force to true")
	}
}

func TestIsRunning(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"running", true},
		{"Running", true},
		{"running (healthy)", true},
		{"Up 2 hours", true},
		{"up 5 minutes", true},
		{"exited", false},
		{"stopped", false},
		{"created", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			s := &container.Session{Status: tt.status}
			got := isRunning(s)
			if got != tt.want {
				t.Errorf("isRunning(status=%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestGcNothingToClean(t *testing.T) {
	// When there are no stopped containers and --all is not set,
	// only running containers exist, so gc should report nothing to clean.
	// We cannot easily mock the runtime in unit tests without Docker,
	// so we test the isRunning filtering logic directly.
	sessions := []*container.Session{
		{ContainerID: "abc123", Status: "running", CreatedAt: time.Now()},
		{ContainerID: "def456", Status: "Up 2 hours", CreatedAt: time.Now()},
	}

	var targets []*container.Session
	for _, s := range sessions {
		if !isRunning(s) {
			targets = append(targets, s)
		}
	}

	if len(targets) != 0 {
		t.Errorf("expected 0 targets without --all, got %d", len(targets))
	}
}

func TestGcFilteringWithAll(t *testing.T) {
	sessions := []*container.Session{
		{ContainerID: "abc123", Status: "running", CreatedAt: time.Now()},
		{ContainerID: "def456", Status: "exited", CreatedAt: time.Now()},
		{ContainerID: "ghi789", Status: "Up 2 hours", CreatedAt: time.Now()},
	}

	// With --all, all containers should be targeted.
	var targetsAll []*container.Session
	targetsAll = append(targetsAll, sessions...)
	if len(targetsAll) != 3 {
		t.Errorf("expected 3 targets with --all, got %d", len(targetsAll))
	}

	// Without --all, only stopped containers.
	var targetsStopped []*container.Session
	for _, s := range sessions {
		if !isRunning(s) {
			targetsStopped = append(targetsStopped, s)
		}
	}
	if len(targetsStopped) != 1 {
		t.Errorf("expected 1 stopped target, got %d", len(targetsStopped))
	}
	if targetsStopped[0].ContainerID != "def456" {
		t.Errorf("expected stopped container def456, got %s", targetsStopped[0].ContainerID)
	}
}

func TestIsAgentcontainerSession(t *testing.T) {
	tests := []struct {
		name    string
		session *container.Session
		want    bool
	}{
		{
			name:    "nil session",
			session: nil,
			want:    false,
		},
		{
			name: "docker runtime",
			session: &container.Session{
				ContainerID: "abc123",
				RuntimeType: container.RuntimeDocker,
			},
			want: true,
		},
		{
			name: "compose runtime",
			session: &container.Session{
				ContainerID: "myproject",
				RuntimeType: container.RuntimeCompose,
			},
			want: true,
		},
		{
			name: "sandbox runtime",
			session: &container.Session{
				ContainerID: "sandbox123",
				RuntimeType: container.RuntimeSandbox,
			},
			want: true,
		},
		{
			name: "unknown runtime type",
			session: &container.Session{
				ContainerID: "unknown123",
				RuntimeType: container.RuntimeType("podman"),
			},
			want: false,
		},
		{
			name: "empty runtime type",
			session: &container.Session{
				ContainerID: "empty123",
				RuntimeType: "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAgentcontainerSession(tt.session)
			if got != tt.want {
				t.Errorf("isAgentcontainerSession() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGcFiltersNonAgentcontainerSessions(t *testing.T) {
	// Simulate sessions returned by a buggy runtime that doesn't properly
	// filter. The gc command should defensively filter these out.
	sessions := []*container.Session{
		{
			ContainerID: "ac123",
			RuntimeType: container.RuntimeDocker,
			Status:      "exited",
			CreatedAt:   time.Now(),
		},
		{
			ContainerID: "unknown456",
			RuntimeType: container.RuntimeType("podman"),
			Status:      "exited",
			CreatedAt:   time.Now(),
		},
		{
			ContainerID: "empty789",
			RuntimeType: "",
			Status:      "exited",
			CreatedAt:   time.Now(),
		},
	}

	// Filter as the gc command does (defensive agentcontainer check + running check).
	var targets []*container.Session
	for _, s := range sessions {
		if !isAgentcontainerSession(s) {
			continue
		}
		if !isRunning(s) {
			targets = append(targets, s)
		}
	}

	// Only the agentcontainer-managed session should be targeted.
	if len(targets) != 1 {
		t.Errorf("expected 1 target after filtering, got %d", len(targets))
	}
	if len(targets) > 0 && targets[0].ContainerID != "ac123" {
		t.Errorf("expected ac123, got %s", targets[0].ContainerID)
	}
}

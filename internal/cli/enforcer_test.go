package cli

import (
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

func TestEnforcerCommandStructure(t *testing.T) {
	cmd := newEnforcerCmd()

	if cmd.Use != "enforcer" {
		t.Errorf("expected Use %q, got %q", "enforcer", cmd.Use)
	}

	// Verify parent has exactly 4 subcommands: start, stop, status, diagnose.
	subCmds := cmd.Commands()
	if len(subCmds) != 4 {
		t.Fatalf("expected 4 subcommands, got %d", len(subCmds))
	}

	wantNames := map[string]bool{
		"start":    false,
		"stop":     false,
		"status":   false,
		"diagnose": false,
	}

	for _, sub := range subCmds {
		if _, ok := wantNames[sub.Use]; !ok {
			t.Errorf("unexpected subcommand %q", sub.Use)
		}
		wantNames[sub.Use] = true
	}

	for name, found := range wantNames {
		if !found {
			t.Errorf("missing subcommand %q", name)
		}
	}
}

func TestEnforcerStartDefaultFlags(t *testing.T) {
	cmd := newEnforcerStartCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	imageVal, err := cmd.Flags().GetString("image")
	if err != nil {
		t.Fatalf("unexpected error getting image flag: %v", err)
	}
	if imageVal != sidecar.DefaultEnforcerImage {
		t.Errorf("expected default image %q, got %q", sidecar.DefaultEnforcerImage, imageVal)
	}

	portVal, err := cmd.Flags().GetInt("port")
	if err != nil {
		t.Fatalf("unexpected error getting port flag: %v", err)
	}
	if portVal != sidecar.DefaultPort {
		t.Errorf("expected default port %d, got %d", sidecar.DefaultPort, portVal)
	}
}

func TestEnforcerStartCustomFlags(t *testing.T) {
	cmd := newEnforcerStartCmd()
	if err := cmd.ParseFlags([]string{"--image", "my-enforcer:v2", "--port", "9090"}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	imageVal, err := cmd.Flags().GetString("image")
	if err != nil {
		t.Fatalf("unexpected error getting image flag: %v", err)
	}
	if imageVal != "my-enforcer:v2" {
		t.Errorf("expected image %q, got %q", "my-enforcer:v2", imageVal)
	}

	portVal, err := cmd.Flags().GetInt("port")
	if err != nil {
		t.Fatalf("unexpected error getting port flag: %v", err)
	}
	if portVal != 9090 {
		t.Errorf("expected port %d, got %d", 9090, portVal)
	}
}

func TestEnforcerStopDefaultFlags(t *testing.T) {
	cmd := newEnforcerStopCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	forceVal, err := cmd.Flags().GetBool("force")
	if err != nil {
		t.Fatalf("unexpected error getting force flag: %v", err)
	}
	if forceVal {
		t.Error("expected --force to default to false")
	}
}

func TestEnforcerStopForceFlag(t *testing.T) {
	cmd := newEnforcerStopCmd()
	if err := cmd.ParseFlags([]string{"--force"}); err != nil {
		t.Fatalf("unexpected error parsing --force flag: %v", err)
	}

	forceVal, err := cmd.Flags().GetBool("force")
	if err != nil {
		t.Fatalf("unexpected error getting force flag: %v", err)
	}
	if !forceVal {
		t.Error("expected --force to be true")
	}
}

func TestEnforcerStatusNoArgs(t *testing.T) {
	cmd := newEnforcerStatusCmd()
	if cmd.Args != nil {
		// cobra.NoArgs is set, so the command should reject extra args.
		err := cmd.Args(cmd, []string{"unexpected"})
		if err == nil {
			t.Error("expected error for extra args")
		}
	}
}

func TestEnforcerFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "enforcer start rejects extra args",
			args:    []string{"enforcer", "start", "unexpected"},
			wantErr: "unknown command",
		},
		{
			name:    "enforcer stop rejects extra args",
			args:    []string{"enforcer", "stop", "unexpected"},
			wantErr: "unknown command",
		},
		{
			name:    "enforcer status rejects extra args",
			args:    []string{"enforcer", "status", "unexpected"},
			wantErr: "unknown command",
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

func TestEnforcerPortFromInspect(t *testing.T) {
	tests := []struct {
		name string
		info container.InspectResponse
		want int
	}{
		{
			name: "no host config",
			info: container.InspectResponse{},
			want: sidecar.DefaultPort,
		},
		{
			name: "empty port bindings",
			info: container.InspectResponse{
				HostConfig: &container.HostConfig{},
			},
			want: sidecar.DefaultPort,
		},
		{
			name: "port binding present",
			info: container.InspectResponse{
				HostConfig: &container.HostConfig{
					PortBindings: map[network.Port][]network.PortBinding{
						network.MustParsePort("50051/tcp"): {
							{HostPort: "50051"},
						},
					},
				},
			},
			want: 50051,
		},
		{
			name: "custom port binding",
			info: container.InspectResponse{
				HostConfig: &container.HostConfig{
					PortBindings: map[network.Port][]network.PortBinding{
						network.MustParsePort("9090/tcp"): {
							{HostPort: "9090"},
						},
					},
				},
			},
			want: 9090,
		},
		{
			name: "invalid port string falls back to default",
			info: container.InspectResponse{
				HostConfig: &container.HostConfig{
					PortBindings: map[network.Port][]network.PortBinding{
						network.MustParsePort("50051/tcp"): {
							{HostPort: ""},
						},
					},
				},
			},
			want: sidecar.DefaultPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enforcerPortFromInspect(tt.info)
			if got != tt.want {
				t.Errorf("enforcerPortFromInspect() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEnforcerRegisteredInRoot(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "enforcer" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'enforcer' subcommand to be registered on root command")
	}
}

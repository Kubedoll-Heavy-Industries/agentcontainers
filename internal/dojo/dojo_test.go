package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	captured    [][]string
	interactive [][]string
}

func (f *fakeRunner) RunCaptured(_ context.Context, _ string, args ...string) (string, error) {
	f.captured = append(f.captured, append([]string(nil), args...))
	if len(args) > 1 && args[1] == "run" {
		return "Session started\n  Container:   abc123def456\n", nil
	}
	return "", nil
}

func (f *fakeRunner) RunInteractive(_ context.Context, _ string, _ io.Reader, _ io.Writer, _ io.Writer, args ...string) error {
	f.interactive = append(f.interactive, append([]string(nil), args...))
	return nil
}

func TestRunNoStartPreparesCodexRedteamConfig(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	runner := &fakeRunner{}

	result, err := Run(context.Background(), Options{
		BaseDir:            dir,
		AgentcontainerPath: "/agentcontainer",
		BuildImage:         true,
		NoStart:            true,
		Stdout:             &out,
		Stderr:             io.Discard,
		Runner:             runner,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ContainerID != "" {
		t.Fatalf("ContainerID = %q, want empty for --no-start", result.ContainerID)
	}
	if len(runner.captured) != 0 {
		t.Fatalf("captured commands = %#v, want none for --no-start", runner.captured)
	}

	data, err := os.ReadFile(filepath.Join(dir, "workspace", "agentcontainer.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	mounts := cfg["mounts"].([]any)
	if mounts[0] != "type=tmpfs,target=/home/node,tmpfs-mode=0777" {
		t.Fatalf("first mount = %v", mounts[0])
	}
	if !strings.Contains(out.String(), "Scoped red-team prompt:") {
		t.Fatalf("output missing scoped prompt:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "/proc/1/root"+result.HostCanaryPath) {
		t.Fatalf("output missing proc-root host canary probe:\n%s", out.String())
	}
}

func TestRunStartsAndDropsIntoCodexChat(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	runner := &fakeRunner{}

	result, err := Run(context.Background(), Options{
		BaseDir:            dir,
		AgentcontainerPath: "/agentcontainer",
		Model:              "gpt-5.5",
		BuildImage:         true,
		Stdout:             &out,
		Stderr:             io.Discard,
		Runner:             runner,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ContainerID != "abc123def456" {
		t.Fatalf("ContainerID = %q", result.ContainerID)
	}
	if len(runner.captured) != 2 {
		t.Fatalf("captured commands = %#v, want docker build and agentcontainer run", runner.captured)
	}
	if runner.captured[0][0] != "docker" || runner.captured[0][1] != "build" {
		t.Fatalf("first captured command = %#v", runner.captured[0])
	}
	if len(runner.interactive) != 1 {
		t.Fatalf("interactive commands = %#v, want one", runner.interactive)
	}
	chat := runner.interactive[0]
	joined := strings.Join(chat, "\x00")
	for _, want := range []string{"/agentcontainer", "exec", "-i", "abc123def456", "codex", "--model", "gpt-5.5"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("chat command %#v missing %q", chat, want)
		}
	}
	if !strings.Contains(chat[len(chat)-1], result.HostCanaryPath) {
		t.Fatalf("prompt argument missing host canary path: %#v", chat)
	}
}

func TestRunRejectsUnknownProfile(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Profile:            "unknown",
		BaseDir:            t.TempDir(),
		AgentcontainerPath: "/agentcontainer",
		NoStart:            true,
		Stdout:             io.Discard,
		Stderr:             io.Discard,
		Runner:             &fakeRunner{},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown dojo profile") {
		t.Fatalf("Run() error = %v, want unknown profile", err)
	}
}

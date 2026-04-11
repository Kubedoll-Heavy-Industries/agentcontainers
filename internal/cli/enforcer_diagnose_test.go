package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiagnoseCommandStructure(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()

	if cmd.Use != "diagnose" {
		t.Errorf("expected Use %q, got %q", "diagnose", cmd.Use)
	}
}

func TestDiagnoseRegisteredInEnforcer(t *testing.T) {
	cmd := newEnforcerCmd()

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "diagnose" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'diagnose' subcommand registered on enforcer command")
	}
}

func TestDiagnoseOutputFormat(t *testing.T) {
	// The diagnose command should produce structured output with check names.
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should contain diagnostic check headers.
	checks := []string{
		"Kernel Version",
		"Cgroup Version",
		"BPF Support",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing check %q\noutput: %s", check, output)
		}
	}
}

func TestDiagnoseSkipDockerFlag(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()
	if err := cmd.ParseFlags([]string{"--skip-docker"}); err != nil {
		t.Fatalf("unexpected error parsing --skip-docker: %v", err)
	}

	skipVal, err := cmd.Flags().GetBool("skip-docker")
	if err != nil {
		t.Fatalf("unexpected error getting skip-docker flag: %v", err)
	}
	if !skipVal {
		t.Error("expected --skip-docker to be true")
	}
}

func TestDiagnoseDefaultFlags(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	skipVal, err := cmd.Flags().GetBool("skip-docker")
	if err != nil {
		t.Fatalf("unexpected error getting skip-docker flag: %v", err)
	}
	if skipVal {
		t.Error("expected --skip-docker to default to false")
	}
}

func TestDiagnoseContainsPlatformInfo(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Platform") {
		t.Errorf("output missing Platform check\noutput: %s", output)
	}
	if !strings.Contains(output, "Nested Container") {
		t.Errorf("output missing Nested Container check\noutput: %s", output)
	}
}

func TestDiagnoseContainsSummary(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Result:") {
		t.Errorf("output missing summary Result line\noutput: %s", output)
	}
}

func TestDiagnoseEnforcerHealthSkipped(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Enforcer Health") {
		t.Errorf("output missing Enforcer Health check\noutput: %s", output)
	}
	if !strings.Contains(output, "SKIP") {
		t.Errorf("expected Enforcer Health to show SKIP when --skip-docker is set\noutput: %s", output)
	}
}

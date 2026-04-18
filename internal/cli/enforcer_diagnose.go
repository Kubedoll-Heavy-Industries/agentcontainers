package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

func newEnforcerDiagnoseCmd() *cobra.Command {
	var skipDocker bool

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Check BPF enforcement prerequisites and report issues",
		Long: `Run diagnostic checks for BPF enforcement:
  - Kernel version and BPF support
  - Cgroup v2 mount and driver
  - Enforcer sidecar health
  - Nested container detection

Use this to debug enforcement issues in CI or development environments.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnforcerDiagnose(cmd, skipDocker)
		},
	}

	cmd.Flags().BoolVar(&skipDocker, "skip-docker", false, "Skip Docker-dependent checks")

	return cmd
}

type diagCheck struct {
	Name   string
	Status string // "PASS", "WARN", "FAIL", "SKIP", "INFO"
	Detail string
}

func runEnforcerDiagnose(cmd *cobra.Command, skipDocker bool) error {
	out := cmd.OutOrStdout()
	var checks []diagCheck

	_, _ = fmt.Fprintln(out, "agentcontainer-enforcer diagnostics")
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 50))

	// Check 1: Platform
	checks = append(checks, diagCheck{
		Name:   "Platform",
		Status: "INFO",
		Detail: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	})

	// Check 2: Kernel version (Linux only)
	checks = append(checks, checkKernelVersion())

	// Check 3: Cgroup v2
	checks = append(checks, checkCgroupVersion())

	// Check 4: BPF support
	checks = append(checks, checkBPFSupport())

	// Check 5: Nested container detection
	checks = append(checks, checkNestedContainer())

	// Check 6: Enforcer sidecar health (requires Docker)
	if skipDocker {
		checks = append(checks, diagCheck{
			Name:   "Enforcer Health",
			Status: "SKIP",
			Detail: "--skip-docker",
		})
	} else {
		checks = append(checks, checkEnforcerHealth())
	}

	// Print results
	for _, c := range checks {
		_, _ = fmt.Fprintf(out, "  %-22s [%s] %s\n", c.Name, c.Status, c.Detail)
	}

	// Summary
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 50))
	fails := 0
	warns := 0
	for _, c := range checks {
		if c.Status == "FAIL" {
			fails++
		}
		if c.Status == "WARN" {
			warns++
		}
	}
	if fails > 0 {
		_, _ = fmt.Fprintf(out, "Result: %d FAIL, %d WARN — BPF enforcement may not work\n", fails, warns)
	} else if warns > 0 {
		_, _ = fmt.Fprintf(out, "Result: %d WARN — BPF enforcement may be degraded\n", warns)
	} else {
		_, _ = fmt.Fprintln(out, "Result: all checks passed")
	}

	return nil
}

func checkKernelVersion() diagCheck {
	if runtime.GOOS != "linux" {
		return diagCheck{
			Name:   "Kernel Version",
			Status: "WARN",
			Detail: fmt.Sprintf("BPF enforcement requires Linux (running %s)", runtime.GOOS),
		}
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return diagCheck{Name: "Kernel Version", Status: "FAIL", Detail: err.Error()}
	}
	version := strings.TrimSpace(string(data))
	// Extract just the version number
	parts := strings.Fields(version)
	if len(parts) >= 3 {
		version = parts[2]
	}
	return diagCheck{Name: "Kernel Version", Status: "PASS", Detail: version}
}

func checkCgroupVersion() diagCheck {
	if runtime.GOOS != "linux" {
		return diagCheck{
			Name:   "Cgroup Version",
			Status: "WARN",
			Detail: "cgroup checks require Linux",
		}
	}
	// Check for cgroup2 unified hierarchy
	if info, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil && !info.IsDir() {
		return diagCheck{Name: "Cgroup Version", Status: "PASS", Detail: "cgroup2 (unified)"}
	}
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		return diagCheck{Name: "Cgroup Version", Status: "WARN", Detail: "cgroup v1 or hybrid — BPF cgroup hooks require cgroup v2"}
	}
	return diagCheck{Name: "Cgroup Version", Status: "FAIL", Detail: "/sys/fs/cgroup not found"}
}

func checkBPFSupport() diagCheck {
	if runtime.GOOS != "linux" {
		return diagCheck{
			Name:   "BPF Support",
			Status: "WARN",
			Detail: "BPF requires Linux",
		}
	}
	// Check if /sys/fs/bpf is mounted (bpffs)
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return diagCheck{Name: "BPF Support", Status: "FAIL", Detail: "/sys/fs/bpf not mounted"}
	}
	return diagCheck{Name: "BPF Support", Status: "PASS", Detail: "/sys/fs/bpf available"}
}

func checkNestedContainer() diagCheck {
	// Heuristic: check for /.dockerenv or /run/.containerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return diagCheck{
			Name:   "Nested Container",
			Status: "WARN",
			Detail: "running inside Docker — BPF cgroup attachment may be limited",
		}
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return diagCheck{
			Name:   "Nested Container",
			Status: "WARN",
			Detail: "running inside a container — BPF cgroup attachment may be limited",
		}
	}
	return diagCheck{Name: "Nested Container", Status: "PASS", Detail: "not detected"}
}

func checkEnforcerHealth() diagCheck {
	target := fmt.Sprintf("127.0.0.1:%d", sidecar.DefaultPort)
	if addr := os.Getenv("AC_ENFORCER_ADDR"); addr != "" {
		target = addr
	}
	if enforcement.ProbeEnforcerHealth(target) {
		return diagCheck{Name: "Enforcer Health", Status: "PASS", Detail: fmt.Sprintf("SERVING at %s", target)}
	}
	return diagCheck{
		Name:   "Enforcer Health",
		Status: "WARN",
		Detail: fmt.Sprintf("not reachable at %s — start with: agentcontainer enforcer start", target),
	}
}

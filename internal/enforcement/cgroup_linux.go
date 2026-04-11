//go:build linux

package enforcement

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCgroupPath returns the cgroup v2 filesystem path for a Docker container.
// It checks well-known paths for systemd and cgroupfs drivers, then falls back
// to a recursive search under the cgroup2 mount point.
func ResolveCgroupPath(containerID string) (string, error) {
	if containerID == "" {
		return "", fmt.Errorf("enforcement: empty container ID")
	}

	mountPoint, err := findCgroup2Mount()
	if err != nil {
		return "", fmt.Errorf("enforcement: finding cgroup2 mount: %w", err)
	}

	// Well-known paths for common cgroup driver configurations.
	candidates := []string{
		// systemd driver (most common on modern distros).
		filepath.Join(mountPoint, "system.slice", "docker-"+containerID+".scope"),
		// cgroupfs driver.
		filepath.Join(mountPoint, "docker", containerID),
	}

	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path, nil
		}
	}

	// Fallback: walk the cgroup hierarchy looking for the container ID.
	// This handles nested cgroups (e.g., Docker-in-Docker, GitHub Actions)
	// where the container cgroup may be under an unexpected parent.
	systemdDir := "docker-" + containerID + ".scope"
	found, err := findCgroupDir(mountPoint, containerID, systemdDir)
	if err != nil {
		return "", fmt.Errorf("enforcement: searching cgroup hierarchy: %w", err)
	}
	if found != "" {
		return found, nil
	}

	return "", fmt.Errorf("enforcement: cgroup path not found for container %s", containerID)
}

// findCgroupDir walks the cgroup hierarchy under root looking for a directory
// whose name matches either the full container ID or the systemd scope name.
// It limits depth to avoid traversing excessively deep hierarchies.
func findCgroupDir(root, containerID, systemdDir string) (string, error) {
	const maxDepth = 5
	var result string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		// Limit traversal depth.
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > maxDepth {
			return filepath.SkipDir
		}

		name := d.Name()
		if name == containerID || name == systemdDir {
			result = path
			return filepath.SkipAll
		}
		return nil
	})

	return result, err
}

// findCgroup2Mount finds the cgroup v2 mount point by reading /proc/mounts.
func findCgroup2Mount() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // best-effort cleanup

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("cgroup2 not mounted")
}

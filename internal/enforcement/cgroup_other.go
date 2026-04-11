//go:build !linux

package enforcement

import "fmt"

// ResolveCgroupPath constructs the expected cgroup v2 path for a Docker
// container when running on a non-Linux host (e.g., macOS with Docker Desktop).
// The actual cgroup exists inside the Docker Desktop Linux VM; we construct it
// using the standard Docker cgroupfs convention. The enforcer sidecar (running
// inside the VM) validates it.
func ResolveCgroupPath(containerID string) (string, error) {
	if containerID == "" {
		return "", fmt.Errorf("enforcement: empty container ID")
	}
	// Docker Desktop's Linux VM uses cgroupfs driver by default.
	return "/sys/fs/cgroup/docker/" + containerID, nil
}

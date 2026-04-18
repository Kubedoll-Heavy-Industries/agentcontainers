# Building and Running agentcontainer-enforcer Container

## Build

Build the multi-stage Docker image:

```bash
cd enforcer
docker build -t agentcontainer-enforcer:latest .
```

For a specific platform (e.g., Linux amd64):

```bash
docker buildx build --platform linux/amd64 -t agentcontainer-enforcer:latest .
```

## Run

The agentcontainer-enforcer requires elevated capabilities to load BPF programs and attach to cgroups:

```bash
docker run \
  --rm \
  --cap-add BPF \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --pid host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -p 127.0.0.1:50051:50051 \
  agentcontainer-enforcer:latest \
  --listen 0.0.0.0:50051
```

### Required Capabilities

- `CAP_BPF`: Load BPF programs
- `CAP_NET_ADMIN`: Attach network BPF programs
- `CAP_SYS_ADMIN`: Attach LSM hooks and manage cgroup BPF

### Required Mounts

- `/sys/fs/bpf`: BPF filesystem for pinned maps/programs
- `/sys/fs/cgroup`: Cgroup v2 filesystem for attaching BPF programs (read-only)

### PID Namespace

`--pid host` is required for the enforcer to access all container PIDs and cgroups.

## Docker Compose

See the example in `Dockerfile` header or use this snippet:

```yaml
services:
  agentcontainer-enforcer:
    build:
      context: .
      dockerfile: Dockerfile
    image: agentcontainer-enforcer:latest
    cap_add:
      - BPF
      - NET_ADMIN
      - SYS_ADMIN
    pid: host
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    ports:
      - "127.0.0.1:50051:50051"
    healthcheck:
      test: ["CMD", "/bin/grpc_health_probe", "-addr=localhost:50051", "-service=agentcontainers.enforcer.v1.Enforcer"]
      interval: 10s
      timeout: 5s
      retries: 3
```

## Configuration

The agentcontainer-enforcer accepts the following flags:

- `--listen <addr>`: gRPC listen address (default: `127.0.0.1:50051`)
- `--socket <path>`: Unix socket path (optional, in addition to TCP)
- `--log-level <level>`: Log level (trace, debug, info, warn, error)

Example with custom config:

```bash
docker run ... agentcontainer-enforcer:latest \
  --listen 0.0.0.0:50051 \
  --log-level debug
```

## Health Check

The container uses `grpc_health_probe` to verify the enforcer's gRPC service is healthy via the standard gRPC health checking protocol (implemented by tonic-health). The probe is downloaded in a separate build stage and supports multi-arch (amd64/arm64) via Docker BuildKit's `TARGETARCH`.

```
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD ["/bin/grpc_health_probe", "-addr=localhost:50051", "-service=agentcontainers.enforcer.v1.Enforcer"]
```

The health probe version can be overridden at build time:

```bash
docker build --build-arg GRPC_HEALTH_PROBE_VERSION=v0.4.35 -t agentcontainer-enforcer:latest .
```

## Security Notes

1. The container runs as non-root user `enforcer` (UID 65532)
2. Elevated capabilities are required for BPF operations
3. The container needs access to host PID namespace and cgroups
4. For production: restrict network exposure (bind to 127.0.0.1 on host)
5. For production: use read-only filesystem (`--read-only`) and tmpfs mounts

## Kernel Requirements

- Linux kernel 5.15+ (for BPF LSM support)
- CONFIG_BPF_LSM=y
- CONFIG_BPF_SYSCALL=y
- cgroup v2 mounted at `/sys/fs/cgroup`

# OpenCode Agent Example

Run [OpenCode](https://opencode.ai) inside an agentcontainer with network egress restricted to the Anthropic API.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- An Anthropic API key (set `ANTHROPIC_API_KEY` in your shell)

## Usage

```bash
cd examples/opencode

# Start the container
agentcontainer run

# In another terminal, exec into it
agentcontainer exec <container-id> -- opencode run "what is 2+2"
```

## What this demonstrates

- **Network policy**: only `api.anthropic.com:443` and `opencode.ai:443` are reachable
- **Secret injection**: `ANTHROPIC_API_KEY` is injected via tmpfs at `/run/secrets/`, never in env vars
- **Tool allowlist**: only `opencode` and `git` are permitted
- **Read-only rootfs**: the container filesystem is immutable except for `/workspace`

## Adapting for other providers

To use OpenAI instead of Anthropic, change the egress rule and secret:

```jsonc
"egress": [{ "host": "api.openai.com", "port": 443 }],
"secrets": {
  "OPENAI_API_KEY": { "provider": "env://OPENAI_API_KEY" }
}
```

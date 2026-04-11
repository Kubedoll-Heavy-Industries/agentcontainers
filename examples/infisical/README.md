# Infisical Secrets Provider

Demonstrates secret injection using Infisical with Machine Identity authentication. The `ac` runtime authenticates via Universal Auth (client credentials flow), fetches secrets from the Infisical API, and injects them at `/run/secrets/`.

## Prerequisites

- Docker and Docker Compose (for local Infisical instance) **or** an Infisical Cloud account
- `ac` CLI

## Quick Start (Infisical Cloud)

```bash
# 1. Create a Machine Identity in Infisical Dashboard
#    Settings > Machine Identities > Create
#    Save the Client ID and Client Secret

# 2. Set host-side credentials (never enter the container)
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"

# 3. Create secrets in your Infisical project
#    - /api-keys/service-x
#    - /databases/staging-postgres (with "password" key)
#    - /payments/stripe (with "secret_key" key)

# 4. Run the agent container
ac run --config agentcontainer.json .
```

## Quick Start (Self-Hosted)

```bash
# 1. Start local Infisical
docker compose up -d

# 2. Open http://localhost:8080, create an account, and set up a project

# 3. Create a Machine Identity and add secrets via the dashboard

# 4. Export credentials and run
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"
ac run --config agentcontainer.json .
```

## Secrets in This Example

| Secret | Path | Environment | TTL | Description |
|--------|------|-------------|-----|-------------|
| `API_KEY` | `/api-keys/service-x` | prod | 1h | Third-party API key |
| `DB_PASSWORD` | `/databases/staging-postgres` | staging | 1h | Database password |
| `STRIPE_KEY` | `/payments/stripe` | prod | 4h | Stripe secret key |

## How It Works

1. `ac run` reads the `secrets` block from `agentcontainer.json`
2. The Secrets Manager authenticates to Infisical using Machine Identity credentials stored on the host
3. Universal Auth exchanges client ID + secret for a short-lived access token
4. Secrets are fetched from the Infisical API for the specified project/environment/path
5. Values are written to `/run/secrets/<NAME>` (tmpfs, mode 0400)
6. TTL-based polling refreshes secrets (e.g., `API_KEY` re-fetches every 55 minutes)
7. All accesses appear in Infisical's audit trail, correlated by Machine Identity

## Per-Tool Scoping

- `DB_PASSWORD` is only accessible to the `mcp-postgres` MCP server
- `STRIPE_KEY` is only accessible to the `mcp-stripe` MCP server
- `API_KEY` has no restriction (available to all tools)

## Production Notes

- Machine Identity credentials live on the host only, never inside the container
- Use Infisical's secret rotation for database passwords and API keys
- Enable Infisical's IP allowlisting for Machine Identities
- Set access token TTL in Infisical to match or exceed your `ac` session timeout

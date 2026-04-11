# Vault / OpenBao Secrets Provider

Demonstrates dynamic secret injection using HashiCorp Vault or OpenBao. The Vault Agent sidecar authenticates to Vault, fetches credentials, writes them to `/run/secrets/`, and handles lease renewal automatically.

## Prerequisites

- Docker and Docker Compose
- `vault` CLI ([install guide](https://developer.hashicorp.com/vault/install))
- `ac` CLI

## Quick Start

```bash
# 1. Start local Vault dev server
docker compose up -d

# 2. Configure Vault with example secrets engines
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
chmod +x setup.sh && ./setup.sh

# 3. Run the agent container
ac run --config agentcontainer.json .
```

## Secrets in This Example

| Secret | Engine | Path | TTL | Description |
|--------|--------|------|-----|-------------|
| `DB_PASSWORD` | Database | `database/creds/agent-readonly` | 1h | Dynamic DB credentials, auto-revoked on session end |
| `AWS_SESSION` | AWS STS | `aws/sts/agent-deploy-role` | 15m | Temporary AWS credentials with scoped permissions |
| `API_KEY` | KV v2 | `secret/data/agents/api-key` | 4h | Static API key with versioning |

## How It Works

1. `ac run` reads the `secrets` block from `agentcontainer.json`
2. The Secrets Manager starts a Vault Agent sidecar alongside the agent container
3. Vault Agent authenticates using the `ac` OIDC JWT (or AppRole in dev mode)
4. Secrets are fetched and written to `/run/secrets/<NAME>` (tmpfs, mode 0400)
5. Rotation happens automatically — `DB_PASSWORD` refreshes every 55 minutes
6. On session end, all Vault leases are explicitly revoked

## Using OpenBao

OpenBao is API-compatible with Vault. Replace the Docker image:

```yaml
# In docker-compose.yml
image: openbao/openbao:latest
```

The `agentcontainer.json` configuration is identical — set `VAULT_ADDR` to point at your OpenBao instance.

## Production Notes

- Replace `dev-root-token` with proper AppRole or OIDC authentication
- Configure Vault's audit log for compliance
- Set appropriate `max_ttl` on database roles
- Use Vault namespaces for multi-tenant isolation

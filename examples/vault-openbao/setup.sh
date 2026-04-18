#!/usr/bin/env bash
# Set up a local Vault dev server with the secrets engines used in this example.
# Requires: vault CLI, a running Vault dev server (see docker-compose.yml).
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
export VAULT_ADDR VAULT_TOKEN

echo "==> Enabling KV v2 secrets engine..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "    (already enabled)"

echo "==> Writing sample API key to secret/data/agents/api-key..."
vault kv put secret/agents/api-key value="sk-placeholder-replace-me"

echo "==> Enabling database secrets engine..."
vault secrets enable -path=database database 2>/dev/null || echo "    (already enabled)"

echo "==> Enabling AWS secrets engine (mock config)..."
vault secrets enable -path=aws aws 2>/dev/null || echo "    (already enabled)"

echo "==> Creating agent-readonly database role (placeholder config)..."
vault write database/roles/agent-readonly \
  db_name=mydb \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="4h" 2>/dev/null || echo "    (requires database connection — configure db_name for your setup)"

echo "==> Enabling JWT auth method for ac OIDC integration..."
vault auth enable jwt 2>/dev/null || echo "    (already enabled)"

echo ""
echo "Vault is ready. Update VAULT_ADDR in your environment:"
echo "  export VAULT_ADDR=${VAULT_ADDR}"
echo "  export VAULT_TOKEN=${VAULT_TOKEN}"
echo ""
echo "To run the agent container:"
echo "  agentcontainer run --config agentcontainer.json ."

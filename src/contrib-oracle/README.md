# DevCoin Contribution Oracle (Go)

Receives GitHub webhooks, verifies authenticity, computes rewards, and mints DevCoin via blockchain node API.

## Run

Set the required environment variables and start the server:

```bash
GITHUB_WEBHOOK_SECRET="old-secret,new-secret" \  # supports rotation: comma-separated
REPO_WHITELIST="owner/repo" \                   # required: only these repos are accepted
BLOCKCHAIN_API="http://127.0.0.1:8080" \        # DevCoin node URL
ORACLE_NODE_TOKEN="<shared-token>" \            # optional: token to auth to node /mint
ORACLE_PROPOSER="authority1" \                  # optional: proposer ID (must be authorized on node)
MAINTAINERS="alice,bob" \                        # optional: usernames treated as maintainers
ORACLE_ADDR=":8090" \                            # optional: bind address
go run ./cmd/oracle
```

## Configuration

- GITHUB_WEBHOOK_SECRET: Webhook secret. To rotate, provide multiple comma-separated values; any will validate.
- REPO_WHITELIST: Comma-separated list of allowed `owner/repo` full names; others are ignored.
- BLOCKCHAIN_API: Base URL of the DevCoin node (default http://127.0.0.1:8080).
- ORACLE_NODE_TOKEN: Optional bearer token the oracle sends to the node (Authorization: Bearer …) for /mint.
- ORACLE_PROPOSER: Proposer ID used in mint requests; must be listed in the node's DEVCOIN_AUTHORITIES. Defaults to `authority1`.
- MAINTAINERS: Comma-separated usernames considered maintainers (used by reward filters for push events).
- ORACLE_ADDR: Bind address (default :8090).

## Endpoints

- POST /webhook — Receives GitHub events. Validates signature (HMAC SHA-256) against any configured secret.
- GET /healthz — Liveness probe.

## Reward rules (MVP)

- Pull Request Merged: 100 DEV
- Issue Closed/Resolved: 25 DEV (closer)
- Code Review Approved: 10 DEV (approver)
- Commit to Whitelisted Repo: 50 DEV for non-maintainers on main branch; deletion-only commits ignored
- Documentation PR (labels docs/documentation or [docs] in title): 25 DEV
- File Deleted only: 0 DEV

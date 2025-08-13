# DevCoin

DevCoin is a minimal blockchain-powered reward system for open-source work. It verifies GitHub activity (PRs, issues, reviews, commits) via a Contribution Oracle and mints tokens on a simple Proof‑of‑Authority (PoA) chain to reward contributors.

Purpose:

- Fairly reward real OSS contributions with transparent on-chain records
- Keep the stack simple to run locally and extend incrementally
- Serve as an educational/reference project for event-driven token issuance

---

## Monorepo structure

```text
src/
  blockchain-node/  # Rust PoA node with REST API + JSON snapshot persistence
  contrib-oracle/   # Go webhook service that validates GitHub events and mints via the node
  frontend/         # React + Vite UI for balances, chain, mint, transfer
LICENSE             # MIT License
README.md           # This file
```

---

## Architecture

- Blockchain Node (Rust)

  - PoA with a static list of authority IDs (env `DEVCOIN_AUTHORITIES`)
  - Transactions: Mint, Transfer
  - REST API: health, mint, transfer, balance, chain
  - Persistence: atomically writes `snapshot.json` to a data dir on each new block
  - Optional bearer token required for `/mint` via `DEVCOIN_MINT_TOKEN`

- Contribution Oracle (Go)

  - Receives GitHub webhooks (HMAC‑SHA256 signature validation)
  - Whitelists repositories; deduplicates events in-memory
  - Reward rules (MVP):
    - PR merged: 100 DEV (25 DEV if docs‑only)
    - Issue closed: 25 DEV
    - PR review approved: 10 DEV
    - Push to main: 50 DEV for non‑maintainers (ignores deletion‑only commits)
  - Calls node `/mint` using a shared token (`ORACLE_NODE_TOKEN`)

- Frontend (React)
  - Simple UI to check balances, view the chain, mint, and transfer
  - Dev proxy from `/api/*` → node to avoid CORS

---

## Quick start

1. Run the Node (Rust)

```bash
# Required: authority list (default is "authority1")
export DEVCOIN_AUTHORITIES="authority1"

# Optional: where to persist the ledger snapshot
export DEVCOIN_DATA_DIR="/home/Chuck/Documents/DevCoin-Project/.devcoin-data"

# Recommended: protect /mint with a shared token
export DEVCOIN_MINT_TOKEN="super-secret-token"

cargo run --manifest-path src/blockchain-node/Cargo.toml
```

Node listens on http://127.0.0.1:8080.

1. Run the Oracle (Go)

```bash
export GITHUB_WEBHOOK_SECRET="my-secret,rotating-secret"   # supports comma-separated secrets
export REPO_WHITELIST="owner/repo"                         # comma-separated full names
export BLOCKCHAIN_API="http://127.0.0.1:8080"              # node base URL
export ORACLE_NODE_TOKEN="super-secret-token"              # must match DEVCOIN_MINT_TOKEN
export ORACLE_PROPOSER="authority1"                        # proposer must be in DEVCOIN_AUTHORITIES
export MAINTAINERS="alice,bob"                             # optional, for push filtering
export ORACLE_ADDR=":8090"

go run ./src/contrib-oracle/cmd/oracle
```

Expose the oracle with your preferred tunnel (e.g., ngrok) and add the webhook to your GitHub repo.

1. Run the Frontend (React)

```bash
cd src/frontend
npm install
# optional override of target node URL for the dev proxy
# VITE_NODE_URL="http://127.0.0.1:8080" \
npm run dev
```

Open http://127.0.0.1:5173/ and paste your token into the “API Token (for /mint)” field when minting.

---

## Blockchain Node (Rust)

Environment

- `DEVCOIN_AUTHORITIES` — comma‑separated authority IDs (default: `authority1`)
- `DEVCOIN_DATA_DIR` — directory for persistence (default: `src/blockchain-node/data`)
- `DEVCOIN_MINT_TOKEN` — if set, `/mint` requires token via `Authorization: Bearer <token>` or `X-Devcoin-Token: <token>`

API

- `GET /health` → "ok"
- `POST /mint` `{ proposer, to, amount }`
- `POST /transfer` `{ proposer, from, to, amount }`
- `GET /balance/:user` → `{ user, balance }`
- `GET /chain` → full chain JSON

Consensus and Rules (MVP)

- PoA: proposer must be listed in `DEVCOIN_AUTHORITIES`.
- Mint: requires `tx.from == proposer` and proposer is an authority.
- Transfer: no signatures yet; proposer must be an authority; `from` balance is debited.
- Signatures/keys are not implemented in the MVP.

Persistence

- The node writes `snapshot.json` atomically on each new block to the data dir.
- On startup it loads the snapshot; the node is the source of truth for balances.

---

## Contribution Oracle (Go)

Environment

- `GITHUB_WEBHOOK_SECRET` — HMAC secret(s); supports multiple values (comma‑separated) for rotation
- `REPO_WHITELIST` — comma‑separated `owner/repo` full names to accept; others ignored
- `BLOCKCHAIN_API` — node base URL (e.g., `http://127.0.0.1:8080`)
- `ORACLE_NODE_TOKEN` — bearer token sent to node `/mint` (must match node’s `DEVCOIN_MINT_TOKEN`)
- `ORACLE_PROPOSER` — proposer ID (must be authorized on node; default `authority1`)
- `MAINTAINERS` — usernames treated as maintainers (filters push rewards)
- `ORACLE_ADDR` — bind address (default `:8090`)

Endpoints

- `POST /webhook` — GitHub events receiver; validates `X-Hub-Signature-256`
- `GET /healthz` — liveness

Rewards (MVP)

- PR merged: 100 DEV (25 for docs)
- Issue closed: 25 DEV
- PR review approved: 10 DEV
- Push to main: 50 DEV for non‑maintainers; ignores deletion‑only commits

Webhook Setup (GitHub)

1. Settings → Webhooks → Add webhook
2. Payload URL: your oracle URL `/webhook` (e.g., from ngrok)
3. Content type: `application/json`
4. Secret: match `GITHUB_WEBHOOK_SECRET`
5. Select events: Pull requests, Issues, Pull request reviews, Pushes

---

## Frontend (React + Vite)

Dev

```bash
cd src/frontend
npm install
npm run dev
```

Notes

- Dev server proxies `/api/*` to the node URL (default `http://127.0.0.1:8080`; override with `VITE_NODE_URL`).
- Paste your `DEVCOIN_MINT_TOKEN` into the UI to authorize mint operations.

---

## Security notes (MVP)

- Use `DEVCOIN_MINT_TOKEN` to restrict `/mint` to the oracle. Consider protecting `/transfer` similarly.
- Oracle deduplication is in‑memory only; after restart, previously seen events may mint again if re‑delivered.
- Webhook secrets support rotation (comma‑separated values).
- Real signature/keys for transactions and persistent dedup storage are future work.

---

## Roadmap

- Shared token on `/transfer`, multi‑secret rotation for node API
- Persistent dedup store for oracle (file/DB)
- Wallet mapping service (GitHub user → wallet address)
- Docker/Compose, CI, richer tests
- Append‑only block log and stronger durability

---

## License

MIT — see [LICENSE](./LICENSE).

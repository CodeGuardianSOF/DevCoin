# DevCoin Node (MVP)

A minimal blockchain node implementing a simple Proof of Authority (PoA) consensus for minting and transfers, with a REST API.

## Run

- Ensure Rust is installed (rustup)
- Optionally set `DEVCOIN_AUTHORITIES` as a comma-separated list of authority IDs (default: `authority1`).
- Optionally set `DEVCOIN_DATA_DIR` to a folder to persist chain and balances (default: `src/blockchain-node/data`).
- Optionally set `DEVCOIN_MINT_TOKEN` to require a shared token for `/mint` requests.
- From this folder: `cargo run`

## API

- GET /health -> "ok"
- GET /healthz -> "ok"
- POST /mint { proposer, to, amount }
- POST /transfer { proposer, from, to, amount }
- GET /balance/:user -> { user, balance }
- GET /chain -> full chain

## Notes

- Authorities are hard-coded to ["authority1"]. For MVP, any mint must have proposer == authority and tx.from == proposer.
- Signature validation is not implemented in MVP.
- Persistence: Node writes `snapshot.json` in the data dir on each new block and loads it at startup.

### Auth for /mint

If `DEVCOIN_MINT_TOKEN` is set, `/mint` requires a token via one of:

- `Authorization: Bearer <token>`
- `X-Devcoin-Token: <token>`

# DevCoin Frontend

A tiny React + Vite UI to interact with the DevCoin node.

## Features

- View node health
- Check a user's balance
- Mint and transfer tokens
- Inspect the chain JSON

## Dev

Install deps and run the dev server:

```bash
npm install
npm run dev
```

The dev server proxies `/api/*` to the node at `http://127.0.0.1:8080` (configurable via `VITE_NODE_URL`).

Set DEVCOIN_MINT_TOKEN on the node and paste it into the UI when minting.

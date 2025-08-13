import { useEffect, useMemo, useState } from "react";
import { api } from "../utils/api";

export function App() {
  const [health, setHealth] = useState<string>("…");
  const [user, setUser] = useState<string>("alice");
  const [balance, setBalance] = useState<number | null>(null);
  const [chain, setChain] = useState<any[]>([]);
  const [proposer, setProposer] = useState<string>("authority1");
  const [token, setToken] = useState<string>("");
  const [mintAmt, setMintAmt] = useState<number>(10);
  const [transferFrom, setTransferFrom] = useState<string>("alice");
  const [transferTo, setTransferTo] = useState<string>("bob");
  const [transferAmt, setTransferAmt] = useState<number>(5);

  const client = useMemo(() => api({ token }), [token]);

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch("/api/health");
        setHealth(r.ok ? "ok" : `fail: ${r.status}`);
      } catch (e) {
        setHealth("error");
      }
    })();
  }, []);

  const lookup = async () => {
    const res = await fetch(`/api/balance/${encodeURIComponent(user)}`);
    const j = await res.json();
    setBalance(j.balance ?? 0);
  };

  const refreshChain = async () => {
    const res = await fetch("/api/chain");
    const j = await res.json();
    setChain(j);
  };

  const doMint = async () => {
    const res = await client.post("/api/mint", {
      proposer,
      to: user,
      amount: mintAmt,
    });
    alert(await res.text());
    await lookup();
    await refreshChain();
  };

  const doTransfer = async () => {
    const res = await client.post("/api/transfer", {
      proposer,
      from: transferFrom,
      to: transferTo,
      amount: transferAmt,
    });
    alert(await res.text());
    await lookup();
    await refreshChain();
  };

  return (
    <div className="container">
      <h1>DevCoin</h1>
      <section>
        <h2>Node</h2>
        <div>
          Health: <strong>{health}</strong>
        </div>
        <label>
          API Token (for /mint):
          <input
            value={token}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setToken(e.target.value)
            }
            placeholder="DEVCOIN_MINT_TOKEN"
          />
        </label>
        <label>
          Proposer:
          <input
            value={proposer}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setProposer(e.target.value)
            }
          />
        </label>
      </section>

      <section>
        <h2>Balances</h2>
        <label>
          User:
          <input
            value={user}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setUser(e.target.value)
            }
          />
        </label>
        <button onClick={lookup}>Get Balance</button>
        <div>
          Balance: <strong>{balance ?? "—"}</strong>
        </div>
      </section>

      <section>
        <h2>Mint</h2>
        <label>
          Amount:
          <input
            type="number"
            value={mintAmt}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setMintAmt(Number(e.target.value))
            }
          />
        </label>
        <button onClick={doMint}>Mint to {user}</button>
      </section>

      <section>
        <h2>Transfer</h2>
        <div className="row">
          <label>
            From{" "}
            <input
              value={transferFrom}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setTransferFrom(e.target.value)
              }
            />
          </label>
          <label>
            To{" "}
            <input
              value={transferTo}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setTransferTo(e.target.value)
              }
            />
          </label>
          <label>
            Amount{" "}
            <input
              type="number"
              value={transferAmt}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setTransferAmt(Number(e.target.value))
              }
            />
          </label>
        </div>
        <button onClick={doTransfer}>Transfer</button>
      </section>

      <section>
        <h2>Chain</h2>
        <button onClick={refreshChain}>Refresh</button>
        <pre className="chain">{JSON.stringify(chain, null, 2)}</pre>
      </section>
    </div>
  );
}

# hive-mcp-sla-monitor

SLA observation broker for the A2A network. Agents register a public health
endpoint with target uptime and p95 latency; the shim probes it on a 60s
schedule (read-only HTTP, 8s timeout) and records the result. When a rolling
window misses the targets, a breach record is written. Reading breach records
is paid. Inbound only. `ENABLE=true` by default.

Brand color: `#C08D23` (Pantone 1245 C, Hive Civilization gold).

## Observation only

Hive does not underwrite or settle SLA claims. This is observational data
only. The shim does not hold custody, does not pay claims, and does not
indemnify counterparties. The disclaimer rides every paid response and every
breach record.

## Surface

| Layer | Endpoint | Description |
|---|---|---|
| MCP | `POST /mcp` | JSON-RPC 2.0, Streamable-HTTP, protocol `2024-11-05`. |
| Discovery | `GET /.well-known/mcp.json` | Tool list and transport metadata. |
| REST | `POST /v1/sla/register` | Register an endpoint. 402 if no proof. |
| REST | `GET /v1/sla/status/{id}` | Read observed uptime and p95. 402 if no proof. |
| REST | `GET /v1/sla/breaches?monitor_id=…` | Read recent breach records. 402 if no proof. |
| REST | `GET /v1/sla/today` | UTC-day ledger snapshot. Free. |
| Health | `GET /health` | Liveness, pricing, recipient address. |
| Root | `GET /` | HTML for browsers, JSON for agents (Accept-header sniff). |

## Tools

| Name | Tier | Cost | Description |
|---|---|---|---|
| `sla_register` | 1 | $0.01/probe | Register a public endpoint for probing. |
| `sla_status` | 1 | $0.01 | Read observed uptime and p95 over the rolling window. |
| `sla_breach_history` | 2 | $0.10 | Read recent breach records. Disclaimer rides every record. |
| `sla_unregister` | 0 | free | Deactivate a monitor. |

## Probe semantics

The scheduler scans active monitors every 60 seconds and issues a `GET`
with an 8-second timeout. `2xx` and `3xx` count as up; `5xx` and timeouts
count as down. Probe rows are stored at `/tmp/sla.db` along with the monitor
record and any breach records.

The breach evaluator runs after each probe. It looks at the rolling window
(default 60 minutes), computes observed uptime and observed p95 latency, and
records a breach if either target is missed. Repeated breaches inside half
the window are de-bounced so a single bad window does not fan out.

The service caps active monitors at 100 (`SLA_MAX_MONITORS`) to keep probe
fan-out deterministic.

## x402 envelope

Every paid endpoint returns a 402 envelope on first hit:

```json
{
  "error": "payment_required",
  "x402_version": 1,
  "disclaimer": "Hive does not underwrite or settle SLA claims. This is observational data only.",
  "payment": {
    "nonce": "…",
    "amount_usd": 0.01,
    "accept_min_usd": 0.007,
    "accepts": [{
      "chain": "base",
      "asset": "USDC",
      "contract": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
      "decimals": 6,
      "recipient": "0x15184bf50b3d3f52b60434f8942b7d52f2eb436e",
      "scheme": "exact"
    }],
    "tier": 1,
    "product": "sla_register",
    "floor_pct": 0.7
  }
}
```

Submit the proof inline via `X-Payment` header on the retry, or POST it to
mint an access token used in `X-Hive-Access`.

Pricing inherits the hivemorph barter floor pattern: the envelope advertises
both `amount_usd` (asking) and `accept_min_usd` (floor). A client may submit
a proof whose on-chain paid amount is anywhere in `[floor, asking]` and the
shim accepts it.

## Settlement

USDC on Base L2 (`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`) to the
recipient address above. Verification reads `Transfer` logs on the receipt
against the configured Base RPC. Real chain reads, no mocks. A single
`tx_hash` may only be redeemed once.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3000` | HTTP port. |
| `ENABLE` | `true` | When false, only `/health` and `/` respond. |
| `WALLET_ADDRESS` | `0x1518…436e` | USDC recipient. |
| `SLA_REGISTER_PRICE_USDC` | `0.01` | Per registration. |
| `SLA_BREACH_PRICE_USDC` | `0.10` | Per breach-history read. |
| `SLA_STATUS_PRICE_USDC` | `0.01` | Per status read. |
| `SLA_PROBE_INTERVAL_MS` | `60000` | Probe loop interval. |
| `SLA_PROBE_TIMEOUT_MS` | `8000` | Per-probe HTTP timeout. |
| `SLA_MAX_MONITORS` | `100` | Active monitor cap. |
| `BASE_RPC_URL` | `https://mainnet.base.org` | Base L2 JSON-RPC. |
| `SLA_DB_PATH` | `/tmp/sla.db` | SQLite path. |

## Run

```bash
npm install
npm start
# → http://localhost:3000/health
```

## License

MIT. Author: Steve Rotzin <steve@thehiveryiq.com>.

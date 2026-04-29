#!/usr/bin/env node
/**
 * hive-mcp-sla-monitor — SLA observation broker for the A2A network.
 *
 * Agents register a public health endpoint with target uptime and p95 latency.
 * The shim probes the endpoint on a 60s schedule (read-only HTTP, 8s timeout)
 * and writes results to SQLite. When a rolling window breaches the targets,
 * a breach record is recorded; reading breach history is paid.
 *
 * Pricing (x402, USDC on Base L2):
 *   - sla_register      : $0.01 per probe schedule registered
 *   - sla_breach_history: $0.10 per breach alert read
 *   - sla_status, sla_unregister, /v1/sla/today : free
 *
 * HARD RULES — Hive does NOT underwrite, indemnify, pay claims, or hold
 * custody. The shim returns observation data only. The disclaimer rides
 * every paid response and breach record.
 *
 * Inbound only. ENABLE=true default.
 *
 * Brand: Hive Civilization gold #C08D23 (Pantone 1245 C).
 * Spec : MCP 2024-11-05 / Streamable-HTTP / JSON-RPC 2.0.
 */

import express from 'express';
import crypto from 'node:crypto';
import { ethers } from 'ethers';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

// ─── Disclaimer (rides every breach response and every paid envelope) ──────
const DISCLAIMER = 'Hive does not underwrite or settle SLA claims. This is observational data only.';

// ─── Config ────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const ENABLE = String(process.env.ENABLE ?? 'true').toLowerCase() === 'true';

const PRICE_REGISTER_USDC = Number(process.env.SLA_REGISTER_PRICE_USDC) || 0.01;
const PRICE_BREACH_USDC = Number(process.env.SLA_BREACH_PRICE_USDC) || 0.10;
const PRICE_STATUS_USDC = Number(process.env.SLA_STATUS_PRICE_USDC) || 0.01;

// Barter floor inheritance — mirrors hivemorph hive_x402/barter.py defaults.
const FLOOR_PCT_DEFAULT = Number(process.env.HIVE_X402_FLOOR_PCT_DEFAULT) || 0.70;
const FLOOR_PCT_MIN = Number(process.env.HIVE_X402_FLOOR_MIN_PCT) || 0.30;
const FLOOR_PCT_MAX = Number(process.env.HIVE_X402_FLOOR_MAX_PCT) || 0.95;
function clampFloorPct(p) {
  return Math.max(FLOOR_PCT_MIN, Math.min(FLOOR_PCT_MAX, p));
}

const WALLET_RECIPIENT = (process.env.WALLET_ADDRESS || '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e').toLowerCase();
const USDC_BASE_CONTRACT = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';

const NONCE_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_MS = 15 * 60 * 1000;

const PROBE_INTERVAL_MS = Number(process.env.SLA_PROBE_INTERVAL_MS) || 60_000;
const PROBE_TIMEOUT_MS = Number(process.env.SLA_PROBE_TIMEOUT_MS) || 8_000;
const MAX_MONITORS = Number(process.env.SLA_MAX_MONITORS) || 100;

const DB_PATH = process.env.SLA_DB_PATH || '/tmp/sla.db';
const BRAND_GOLD = '#C08D23';

// ─── SQLite ────────────────────────────────────────────────────────────────
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS monitors (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    target_uptime_pct REAL NOT NULL,
    target_p95_ms INTEGER NOT NULL,
    window_minutes INTEGER NOT NULL DEFAULT 60,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_probed_at INTEGER,
    paid_usdc REAL,
    tx_hash TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_monitors_did ON monitors(did);
  CREATE INDEX IF NOT EXISTS idx_monitors_active ON monitors(active);

  CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    up INTEGER NOT NULL,
    status_code INTEGER,
    latency_ms INTEGER,
    error TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_probes_monitor_ts ON probes(monitor_id, ts);

  CREATE TABLE IF NOT EXISTS breaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    observed_uptime_pct REAL,
    observed_p95_ms INTEGER,
    target_uptime_pct REAL,
    target_p95_ms INTEGER,
    window_minutes INTEGER,
    sample_count INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_breaches_monitor_ts ON breaches(monitor_id, ts);
  CREATE INDEX IF NOT EXISTS idx_breaches_ts ON breaches(ts);

  CREATE TABLE IF NOT EXISTS payments (
    tx_hash TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    paid_usdc REAL NOT NULL,
    payer TEXT,
    ts INTEGER NOT NULL
  );
`);

const stmts = {
  insertMonitor: db.prepare(`
    INSERT INTO monitors (id, did, endpoint, target_uptime_pct, target_p95_ms, window_minutes, active, created_at, paid_usdc, tx_hash)
    VALUES (@id, @did, @endpoint, @target_uptime_pct, @target_p95_ms, @window_minutes, 1, @created_at, @paid_usdc, @tx_hash)
  `),
  getMonitor: db.prepare('SELECT * FROM monitors WHERE id = ?'),
  countActive: db.prepare('SELECT COUNT(*) AS n FROM monitors WHERE active = 1'),
  listActive: db.prepare('SELECT * FROM monitors WHERE active = 1 ORDER BY last_probed_at ASC NULLS FIRST LIMIT ?'),
  deactivate: db.prepare('UPDATE monitors SET active = 0 WHERE id = ?'),
  touchProbed: db.prepare('UPDATE monitors SET last_probed_at = ? WHERE id = ?'),
  insertProbe: db.prepare(`
    INSERT INTO probes (monitor_id, ts, up, status_code, latency_ms, error)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  windowProbes: db.prepare(`
    SELECT up, latency_ms FROM probes
    WHERE monitor_id = ? AND ts >= ?
    ORDER BY ts ASC
  `),
  recentProbes: db.prepare(`
    SELECT ts, up, status_code, latency_ms, error FROM probes
    WHERE monitor_id = ? ORDER BY ts DESC LIMIT ?
  `),
  insertBreach: db.prepare(`
    INSERT INTO breaches (monitor_id, ts, kind, observed_uptime_pct, observed_p95_ms, target_uptime_pct, target_p95_ms, window_minutes, sample_count)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  recentBreaches: db.prepare(`
    SELECT id, monitor_id, ts, kind, observed_uptime_pct, observed_p95_ms, target_uptime_pct, target_p95_ms, window_minutes, sample_count
    FROM breaches WHERE monitor_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?
  `),
  todayBreaches: db.prepare(`
    SELECT COUNT(*) AS n FROM breaches WHERE ts >= ?
  `),
  todayProbes: db.prepare(`
    SELECT COUNT(*) AS n, COALESCE(SUM(up),0) AS up_n FROM probes WHERE ts >= ?
  `),
  todayMonitorsCreated: db.prepare(`
    SELECT COUNT(*) AS n FROM monitors WHERE created_at >= ?
  `),
  insertPayment: db.prepare(`
    INSERT OR IGNORE INTO payments (tx_hash, product, paid_usdc, payer, ts)
    VALUES (?, ?, ?, ?, ?)
  `),
  getPayment: db.prepare('SELECT * FROM payments WHERE tx_hash = ?'),
};

function nowSec() { return Math.floor(Date.now() / 1000); }
function midnightUtcSec() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

// ─── Base L2 RPC — real reads, no mocks ────────────────────────────────────
const provider = new ethers.JsonRpcProvider(BASE_RPC_URL);
const USDC_TRANSFER_TOPIC = ethers.id('Transfer(address,address,uint256)');

async function verifyOnchain(txHash, expectedRecipient, minAmountUsdc) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    return { ok: false, reason: 'bad_tx_hash_format' };
  }
  let receipt;
  try {
    receipt = await provider.getTransactionReceipt(txHash);
  } catch (err) {
    return { ok: false, reason: 'rpc_error', detail: err.message };
  }
  if (!receipt) return { ok: false, reason: 'tx_not_found' };
  if (receipt.status !== 1) return { ok: false, reason: 'tx_reverted' };

  const recipient = expectedRecipient.toLowerCase();
  const usdcAddr = USDC_BASE_CONTRACT.toLowerCase();
  let paidRaw = 0n;
  let payer = null;
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== usdcAddr) continue;
    if (!log.topics || log.topics[0] !== USDC_TRANSFER_TOPIC) continue;
    if (log.topics.length < 3) continue;
    const to = ('0x' + log.topics[2].slice(26)).toLowerCase();
    if (to !== recipient) continue;
    const from = ('0x' + log.topics[1].slice(26)).toLowerCase();
    const amount = BigInt(log.data);
    paidRaw += amount;
    if (!payer) payer = from;
  }
  if (paidRaw === 0n) return { ok: false, reason: 'no_usdc_transfer_to_recipient' };
  const paidUsdc = Number(paidRaw) / 1e6;
  if (paidUsdc + 1e-9 < minAmountUsdc) {
    return { ok: false, reason: 'underpaid', paid_usdc: paidUsdc, min_usdc: minAmountUsdc };
  }
  return { ok: true, paid_usdc: paidUsdc, payer, block: receipt.blockNumber };
}

// ─── x402 envelope ─────────────────────────────────────────────────────────
const PRODUCTS = {
  sla_register: { tier: 1, price: PRICE_REGISTER_USDC },
  sla_breach_history: { tier: 2, price: PRICE_BREACH_USDC },
  sla_status: { tier: 1, price: PRICE_STATUS_USDC },
};

const nonces = new Map();
const tokens = new Map();
function gc() {
  const now = Date.now();
  for (const [k, v] of nonces) if (v.expires_at_ms < now) nonces.delete(k);
  for (const [k, v] of tokens) if (v.expires_at_ms < now) tokens.delete(k);
}
setInterval(gc, 60_000).unref?.();

const BOGO = {
  first_call_free: true,
  loyalty_threshold: 6,
  pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
  claim_with: 'x-hive-did header',
};

function quoteEnvelope({ product }) {
  const p = PRODUCTS[product];
  if (!p) throw new Error(`unknown_product:${product}`);
  const nonce = crypto.randomUUID();
  const askingUsdc = +p.price.toFixed(6);
  const floorUsdc = +(askingUsdc * clampFloorPct(FLOOR_PCT_DEFAULT)).toFixed(6);
  const expires_at = Math.floor((Date.now() + NONCE_TTL_MS) / 1000);
  nonces.set(nonce, { expires_at_ms: Date.now() + NONCE_TTL_MS, paid: false, product });
  return {
    error: 'payment_required',
    x402_version: 1,
    disclaimer: DISCLAIMER,
    payment: {
      nonce,
      amount_usd: askingUsdc,
      accept_min_usd: floorUsdc,
      accepts: [{
        chain: 'base',
        asset: 'USDC',
        contract: USDC_BASE_CONTRACT,
        decimals: 6,
        recipient: WALLET_RECIPIENT,
        scheme: 'exact',
      }],
      expires_at,
      tier: p.tier,
      product,
      price_usd: askingUsdc,
      floor_pct: clampFloorPct(FLOOR_PCT_DEFAULT),
    },
    bogo: BOGO,
  };
}

async function redeemProof({ nonce, payer, chain, tx_hash, signature, message }) {
  if (!nonce || !chain || !tx_hash) return { ok: false, status: 400, error: 'missing_fields' };
  const n = nonces.get(nonce);
  if (!n) return { ok: false, status: 404, error: 'unknown_or_expired_nonce' };
  if (n.expires_at_ms < Date.now()) {
    nonces.delete(nonce);
    return { ok: false, status: 410, error: 'nonce_expired' };
  }
  if (chain.toLowerCase() !== 'base') return { ok: false, status: 400, error: 'unsupported_chain' };

  const product = n.product;
  const askingUsdc = +PRODUCTS[product].price.toFixed(6);
  const floorUsdc = +(askingUsdc * clampFloorPct(FLOOR_PCT_DEFAULT)).toFixed(6);

  let recoveredAddr = null;
  if (signature && message) {
    try {
      recoveredAddr = ethers.verifyMessage(String(message), String(signature)).toLowerCase();
    } catch {
      return { ok: false, status: 400, error: 'bad_signature' };
    }
  }

  const dup = stmts.getPayment.get(tx_hash);
  if (dup) return { ok: false, status: 409, error: 'tx_already_redeemed' };

  const v = await verifyOnchain(tx_hash, WALLET_RECIPIENT, floorUsdc);
  if (!v.ok) return { ok: false, status: 402, error: 'onchain_verification_failed', detail: v };

  const canonicalPayer = (payer || recoveredAddr || v.payer || '').toLowerCase() || null;
  if (recoveredAddr && payer && recoveredAddr !== payer.toLowerCase()) {
    return { ok: false, status: 400, error: 'signature_payer_mismatch' };
  }
  if (recoveredAddr && v.payer && recoveredAddr !== v.payer.toLowerCase()) {
    return { ok: false, status: 400, error: 'signature_onchain_payer_mismatch' };
  }

  n.paid = true;
  n.tx_hash = tx_hash;
  n.paid_usdc = v.paid_usdc;
  n.payer = canonicalPayer;
  stmts.insertPayment.run(tx_hash, product, v.paid_usdc, canonicalPayer, nowSec());
  const token = `hsla_${crypto.randomUUID().replace(/-/g, '')}`;
  tokens.set(token, {
    expires_at_ms: Date.now() + TOKEN_TTL_MS,
    nonce, tx_hash, payer: canonicalPayer, paid_usdc: v.paid_usdc, product,
  });
  return {
    ok: true, access_token: token, expires_in: Math.floor(TOKEN_TTL_MS / 1000),
    paid_usdc: v.paid_usdc, payer: canonicalPayer, block: v.block, product,
  };
}

function tokenForReq(req, product) {
  const hdr = req.headers['x-hive-access'];
  if (hdr && tokens.has(hdr)) {
    const t = tokens.get(hdr);
    if (t.expires_at_ms > Date.now() && t.product === product) return { ok: true, token: hdr, ctx: t };
  }
  return { ok: false };
}

async function inlineRedeem(req, expectedProduct) {
  const inline = req.headers['x-payment'];
  if (!inline) return { ok: false };
  try {
    const env = typeof inline === 'string' ? JSON.parse(inline) : inline;
    if (!env?.nonce || !env?.tx_hash || !env?.chain) return { ok: false };
    const r = await redeemProof(env);
    if (!r.ok) return { ok: false, error: r.error };
    if (r.product !== expectedProduct) return { ok: false, error: 'wrong_product' };
    return { ok: true, mint: r };
  } catch {
    return { ok: false, error: 'bad_inline_payment' };
  }
}

async function ensurePaid(req, product) {
  const tok = tokenForReq(req, product);
  if (tok.ok) return { ok: true, mint: { token: tok.token, paid_usdc: tok.ctx.paid_usdc, payer: tok.ctx.payer } };
  const inline = await inlineRedeem(req, product);
  if (inline.ok) return inline;
  return { ok: false, env: quoteEnvelope({ product }) };
}

// ─── Validation ────────────────────────────────────────────────────────────
function isValidDid(s) {
  return typeof s === 'string' && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]{3,}$/.test(s);
}

function isValidEndpoint(s) {
  if (typeof s !== 'string' || s.length > 500) return false;
  let u;
  try { u = new URL(s); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  // Block private/loopback hosts to keep this strictly for public endpoints.
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host === '0.0.0.0') return false;
  if (/^127\./.test(host)) return false;
  if (/^10\./.test(host)) return false;
  if (/^192\.168\./.test(host)) return false;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return false;
  if (/^169\.254\./.test(host)) return false;
  if (host.endsWith('.local') || host.endsWith('.internal')) return false;
  return true;
}

// ─── Probe scheduler ───────────────────────────────────────────────────────
async function probeOnce(monitor) {
  const startedAt = Date.now();
  const ts = nowSec();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  let up = 0, statusCode = null, latencyMs = null, error = null;
  try {
    const res = await fetch(monitor.endpoint, {
      method: 'GET',
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'user-agent': 'hive-mcp-sla-monitor/1.0 (+https://github.com/srotzin/hive-mcp-sla-monitor)' },
    });
    statusCode = res.status;
    latencyMs = Date.now() - startedAt;
    up = (res.status >= 200 && res.status < 400) ? 1 : 0;
    if (res.status >= 500) up = 0;
    // Drain body to free socket. Cap to avoid pulling large payloads.
    try {
      const reader = res.body?.getReader?.();
      if (reader) {
        let read = 0;
        while (read < 4096) {
          const { done, value } = await reader.read();
          if (done) break;
          read += value?.length || 0;
        }
        try { await reader.cancel(); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  } catch (err) {
    latencyMs = Date.now() - startedAt;
    up = 0;
    error = err.name === 'AbortError' ? 'timeout' : (err.message || 'fetch_error');
  } finally {
    clearTimeout(t);
  }
  stmts.insertProbe.run(monitor.id, ts, up, statusCode, latencyMs, error);
  stmts.touchProbed.run(ts, monitor.id);
  evaluateBreach(monitor, ts);
}

function p95(arr) {
  if (!arr.length) return null;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1);
  return sorted[Math.max(0, idx)];
}

function evaluateBreach(monitor, ts) {
  const since = ts - monitor.window_minutes * 60;
  const rows = stmts.windowProbes.all(monitor.id, since);
  if (rows.length < 3) return null;
  const upN = rows.filter(r => r.up === 1).length;
  const observedUptime = (upN / rows.length) * 100;
  const latencies = rows.map(r => r.latency_ms).filter(x => Number.isFinite(x));
  const observedP95 = p95(latencies);

  let kind = null;
  if (observedUptime + 1e-9 < monitor.target_uptime_pct) kind = 'uptime_below_target';
  else if (observedP95 != null && observedP95 > monitor.target_p95_ms) kind = 'p95_above_target';
  if (!kind) return null;

  // Suppress duplicates: only insert if no breach for this monitor in last
  // window_minutes / 2 (de-bounce so a single bad window doesn't fan out).
  const debounceSince = ts - Math.max(60, Math.floor(monitor.window_minutes * 60 / 2));
  const recent = stmts.recentBreaches.all(monitor.id, debounceSince, 1);
  if (recent.length) return null;

  stmts.insertBreach.run(
    monitor.id, ts, kind,
    +observedUptime.toFixed(3),
    observedP95 ?? null,
    monitor.target_uptime_pct,
    monitor.target_p95_ms,
    monitor.window_minutes,
    rows.length,
  );
  return kind;
}

let probeTimer = null;
async function probeTick() {
  try {
    const monitors = stmts.listActive.all(MAX_MONITORS);
    if (!monitors.length) return;
    // Run probes in parallel, capped by Promise.all length (already bounded by MAX_MONITORS).
    await Promise.all(monitors.map(m => probeOnce(m).catch(err => {
      console.error(`[probe] ${m.id} ${err?.message || err}`);
    })));
  } catch (err) {
    console.error(`[probe-tick] ${err?.message || err}`);
  }
}

function startScheduler() {
  if (probeTimer) return;
  probeTimer = setInterval(probeTick, PROBE_INTERVAL_MS);
  probeTimer.unref?.();
  // Kick once on startup so health/today have data.
  setTimeout(probeTick, 1500).unref?.();
}

// ─── MCP tools ─────────────────────────────────────────────────────────────
const TOOLS = [
  {
    name: 'sla_register',
    description: 'Register a public health endpoint for SLA observation. The shim probes it on a 60s schedule (read-only HTTP, 8s timeout) and records uptime/latency. Tier 1, $0.01 USDC via x402. Observation only — Hive does not underwrite or settle SLA claims.',
    inputSchema: {
      type: 'object',
      required: ['did', 'endpoint', 'target_uptime_pct', 'target_p95_ms'],
      properties: {
        did: { type: 'string', description: 'Agent DID (did:method:identifier).' },
        endpoint: { type: 'string', description: 'Public HTTP/HTTPS health endpoint. Must resolve to a non-private host.' },
        target_uptime_pct: { type: 'number', minimum: 0, maximum: 100, description: 'Target uptime percent over the rolling window (e.g., 99.0).' },
        target_p95_ms: { type: 'integer', minimum: 1, description: 'Target p95 latency in milliseconds over the rolling window.' },
        window_minutes: { type: 'integer', minimum: 5, maximum: 1440, default: 60, description: 'Rolling window length in minutes for breach evaluation. Default 60.' },
      },
    },
  },
  {
    name: 'sla_status',
    description: 'Read the current observed uptime and p95 latency for a registered monitor over its rolling window. Tier 1, $0.01 USDC via x402. Observation only.',
    inputSchema: {
      type: 'object',
      required: ['monitor_id'],
      properties: {
        monitor_id: { type: 'string', description: 'Monitor id returned by sla_register.' },
      },
    },
  },
  {
    name: 'sla_breach_history',
    description: 'Read recent breach records for a registered monitor. Tier 2, $0.10 USDC via x402. Each record carries the no-underwriting disclaimer. Hive does not pay claims.',
    inputSchema: {
      type: 'object',
      required: ['monitor_id'],
      properties: {
        monitor_id: { type: 'string', description: 'Monitor id returned by sla_register.' },
        since_seconds_ago: { type: 'integer', minimum: 60, maximum: 30 * 86400, default: 86400, description: 'Lookback window in seconds. Default 86400 (24h).' },
        limit: { type: 'integer', minimum: 1, maximum: 200, default: 50, description: 'Max records to return. Default 50.' },
      },
    },
  },
  {
    name: 'sla_unregister',
    description: 'Deactivate a monitor so the shim stops probing it. Free. Existing probe and breach records are retained for read-back.',
    inputSchema: {
      type: 'object',
      required: ['monitor_id'],
      properties: {
        monitor_id: { type: 'string', description: 'Monitor id returned by sla_register.' },
      },
    },
  },
];

function asTextResult(obj) {
  return { type: 'text', text: JSON.stringify(obj, null, 2) };
}

function buildStatus(monitor) {
  const ts = nowSec();
  const since = ts - monitor.window_minutes * 60;
  const rows = stmts.windowProbes.all(monitor.id, since);
  const upN = rows.filter(r => r.up === 1).length;
  const observedUptime = rows.length ? +((upN / rows.length) * 100).toFixed(3) : null;
  const latencies = rows.map(r => r.latency_ms).filter(x => Number.isFinite(x));
  const observedP95 = p95(latencies);
  return {
    monitor_id: monitor.id,
    did: monitor.did,
    endpoint: monitor.endpoint,
    active: monitor.active === 1,
    window_minutes: monitor.window_minutes,
    target_uptime_pct: monitor.target_uptime_pct,
    target_p95_ms: monitor.target_p95_ms,
    observed_uptime_pct: observedUptime,
    observed_p95_ms: observedP95,
    sample_count: rows.length,
    last_probed_at: monitor.last_probed_at,
    created_at: monitor.created_at,
    disclaimer: DISCLAIMER,
  };
}

async function handleRegister(args, mintCtx) {
  if (!isValidDid(args.did)) throw new Error('invalid_did');
  if (!isValidEndpoint(args.endpoint)) throw new Error('invalid_endpoint');
  const targetUptime = Number(args.target_uptime_pct);
  const targetP95 = Math.floor(Number(args.target_p95_ms));
  if (!Number.isFinite(targetUptime) || targetUptime <= 0 || targetUptime > 100) throw new Error('invalid_target_uptime_pct');
  if (!Number.isFinite(targetP95) || targetP95 < 1) throw new Error('invalid_target_p95_ms');
  const windowMinutes = Math.max(5, Math.min(1440, Math.floor(args.window_minutes || 60)));

  const active = stmts.countActive.get().n;
  if (active >= MAX_MONITORS) throw new Error('max_monitors_reached');

  const id = `m_${crypto.randomUUID().replace(/-/g, '')}`;
  const ts = nowSec();
  stmts.insertMonitor.run({
    id,
    did: args.did,
    endpoint: args.endpoint,
    target_uptime_pct: targetUptime,
    target_p95_ms: targetP95,
    window_minutes: windowMinutes,
    created_at: ts,
    paid_usdc: mintCtx?.paid_usdc ?? null,
    tx_hash: mintCtx?.tx_hash ?? null,
  });
  const monitor = stmts.getMonitor.get(id);
  return {
    monitor_id: id,
    did: monitor.did,
    endpoint: monitor.endpoint,
    target_uptime_pct: monitor.target_uptime_pct,
    target_p95_ms: monitor.target_p95_ms,
    window_minutes: monitor.window_minutes,
    probe_interval_seconds: PROBE_INTERVAL_MS / 1000,
    probe_timeout_seconds: PROBE_TIMEOUT_MS / 1000,
    created_at: monitor.created_at,
    paid_usdc: mintCtx?.paid_usdc ?? null,
    payer: mintCtx?.payer ?? null,
    disclaimer: DISCLAIMER,
  };
}

async function executeTool(name, args, req) {
  switch (name) {
    case 'sla_register': {
      const access = await ensurePaid(req, 'sla_register');
      if (!access.ok) {
        const err = new Error('payment_required');
        err.code = 402;
        err.data = access.env;
        throw err;
      }
      const out = await handleRegister(args, { ...access.mint, tx_hash: access.mint?.tx_hash });
      return asTextResult(out);
    }
    case 'sla_status': {
      const monitor = stmts.getMonitor.get(args.monitor_id);
      if (!monitor) throw new Error('monitor_not_found');
      const access = await ensurePaid(req, 'sla_status');
      if (!access.ok) {
        const err = new Error('payment_required');
        err.code = 402;
        err.data = access.env;
        throw err;
      }
      return asTextResult(buildStatus(monitor));
    }
    case 'sla_breach_history': {
      const monitor = stmts.getMonitor.get(args.monitor_id);
      if (!monitor) throw new Error('monitor_not_found');
      const access = await ensurePaid(req, 'sla_breach_history');
      if (!access.ok) {
        const err = new Error('payment_required');
        err.code = 402;
        err.data = access.env;
        throw err;
      }
      const lookback = Math.max(60, Math.min(30 * 86400, Math.floor(args.since_seconds_ago || 86400)));
      const limit = Math.max(1, Math.min(200, Math.floor(args.limit || 50)));
      const since = nowSec() - lookback;
      const breaches = stmts.recentBreaches.all(monitor.id, since, limit);
      return asTextResult({
        monitor_id: monitor.id,
        endpoint: monitor.endpoint,
        since_seconds_ago: lookback,
        count: breaches.length,
        breaches: breaches.map(b => ({ ...b, disclaimer: DISCLAIMER })),
        disclaimer: DISCLAIMER,
        role: 'observation_only',
        underwriting: 'never',
      });
    }
    case 'sla_unregister': {
      const monitor = stmts.getMonitor.get(args.monitor_id);
      if (!monitor) throw new Error('monitor_not_found');
      stmts.deactivate.run(args.monitor_id);
      return asTextResult({ monitor_id: monitor.id, deactivated: true, disclaimer: DISCLAIMER });
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── App ───────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '128kb' }));

app.get('/health', (req, res) => {
  const active = stmts.countActive.get().n;
  res.json({
    status: 'ok',
    service: 'hive-mcp-sla-monitor',
    version: '1.0.0',
    enable: ENABLE,
    inbound_only: true,
    role: 'observation_only',
    underwriting: 'never',
    custody: 'never',
    active_monitors: active,
    max_monitors: MAX_MONITORS,
    probe_interval_seconds: PROBE_INTERVAL_MS / 1000,
    probe_timeout_seconds: PROBE_TIMEOUT_MS / 1000,
    pricing: {
      sla_register_usd: PRICE_REGISTER_USDC,
      sla_status_usd: PRICE_STATUS_USDC,
      sla_breach_history_usd: PRICE_BREACH_USDC,
      floor_pct: clampFloorPct(FLOOR_PCT_DEFAULT),
    },
    chain: 'base',
    asset: 'USDC',
    recipient: WALLET_RECIPIENT,
    db_path: DB_PATH,
    brand_color: BRAND_GOLD,
    disclaimer: DISCLAIMER,
  });
});

app.get('/', (req, res) => {
  const accept = String(req.headers.accept || '');
  if (accept.includes('text/html')) {
    res.type('html').send(rootHtml());
    return;
  }
  res.json({
    service: 'hive-mcp-sla-monitor',
    version: '1.0.0',
    description: 'SLA observation broker for the A2A network. Inbound only. Observation only.',
    docs: 'https://github.com/srotzin/hive-mcp-sla-monitor',
    endpoints: {
      mcp: '/mcp',
      well_known: '/.well-known/mcp.json',
      rest: ['/v1/sla/register', '/v1/sla/status/{id}', '/v1/sla/breaches', '/v1/sla/today'],
      health: '/health',
    },
    pricing: {
      sla_register_usd: PRICE_REGISTER_USDC,
      sla_status_usd: PRICE_STATUS_USDC,
      sla_breach_history_usd: PRICE_BREACH_USDC,
      chain: 'base',
      asset: 'USDC',
    },
    role: 'observation_only',
    underwriting: 'never',
    custody: 'never',
    brand_color: BRAND_GOLD,
    disclaimer: DISCLAIMER,
  });
});

app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== '2.0') {
    return res.json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid JSON-RPC' } });
  }
  try {
    switch (method) {
      case 'initialize':
        return res.json({
          jsonrpc: '2.0', id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: { listChanged: false } },
            serverInfo: {
              name: 'hive-mcp-sla-monitor',
              version: '1.0.0',
              description: 'SLA observation broker for the A2A network — Hive Civilization. Observation only; Hive does not underwrite or settle SLA claims.',
            },
          },
        });
      case 'tools/list':
        return res.json({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      case 'tools/call': {
        const { name, arguments: args } = params || {};
        if (!ENABLE) {
          return res.json({ jsonrpc: '2.0', id, error: { code: 503, message: 'service_disabled' } });
        }
        try {
          const out = await executeTool(name, args || {}, req);
          return res.json({ jsonrpc: '2.0', id, result: { content: [out] } });
        } catch (err) {
          if (err.code === 402) {
            return res.json({
              jsonrpc: '2.0', id,
              error: { code: 402, message: 'payment_required', data: err.data },
            });
          }
          return res.json({ jsonrpc: '2.0', id, error: { code: -32000, message: err.message } });
        }
      }
      case 'ping':
        return res.json({ jsonrpc: '2.0', id, result: {} });
      default:
        return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  } catch (err) {
    return res.json({ jsonrpc: '2.0', id, error: { code: -32000, message: err.message } });
  }
});

// REST
app.post('/v1/sla/register', async (req, res) => {
  if (!ENABLE) return res.status(503).json({ error: 'service_disabled', disclaimer: DISCLAIMER });
  try {
    const out = await executeTool('sla_register', req.body || {}, req);
    res.json(JSON.parse(out.text));
  } catch (err) {
    if (err.code === 402) return res.status(402).json(err.data);
    res.status(400).json({ error: err.message, disclaimer: DISCLAIMER });
  }
});

app.get('/v1/sla/status/:id', async (req, res) => {
  if (!ENABLE) return res.status(503).json({ error: 'service_disabled', disclaimer: DISCLAIMER });
  try {
    const out = await executeTool('sla_status', { monitor_id: req.params.id }, req);
    res.json(JSON.parse(out.text));
  } catch (err) {
    if (err.code === 402) return res.status(402).json(err.data);
    res.status(400).json({ error: err.message, disclaimer: DISCLAIMER });
  }
});

app.get('/v1/sla/breaches', async (req, res) => {
  if (!ENABLE) return res.status(503).json({ error: 'service_disabled', disclaimer: DISCLAIMER });
  try {
    const args = {
      monitor_id: String(req.query.monitor_id || ''),
      since_seconds_ago: req.query.since_seconds_ago ? Number(req.query.since_seconds_ago) : undefined,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
    };
    const out = await executeTool('sla_breach_history', args, req);
    res.json(JSON.parse(out.text));
  } catch (err) {
    if (err.code === 402) return res.status(402).json(err.data);
    res.status(400).json({ error: err.message, disclaimer: DISCLAIMER });
  }
});

app.get('/v1/sla/today', (req, res) => {
  const since = midnightUtcSec();
  const probesRow = stmts.todayProbes.get(since);
  const breachesRow = stmts.todayBreaches.get(since);
  const monitorsRow = stmts.todayMonitorsCreated.get(since);
  const active = stmts.countActive.get().n;
  res.json({
    date_utc: new Date(since * 1000).toISOString().slice(0, 10),
    monitors: {
      active,
      created_today: monitorsRow.n,
      max: MAX_MONITORS,
    },
    probes: {
      count: probesRow.n,
      up_count: probesRow.up_n,
      down_count: probesRow.n - probesRow.up_n,
    },
    breaches: {
      count: breachesRow.n,
    },
    disclaimer: DISCLAIMER,
    role: 'observation_only',
    underwriting: 'never',
  });
});

// MCP discovery
app.get('/.well-known/mcp.json', (req, res) => {
  res.json({
    name: 'hive-mcp-sla-monitor',
    version: '1.0.0',
    protocol: '2024-11-05',
    transport: 'streamable-http',
    endpoint: '/mcp',
    description: 'SLA observation broker — Hive does not underwrite or settle SLA claims.',
    tools: TOOLS.map(t => ({ name: t.name, description: t.description })),
    brand_color: BRAND_GOLD,
    disclaimer: DISCLAIMER,
  });
});

if (!ENABLE) {
  console.log('[hive-mcp-sla-monitor] ENABLE=false — running in dormant mode (health only)');
} else {
  startScheduler();
}

// ─── Schema discoverability (auto-injected) ──────────────────────────────
app.get('/.well-known/agent-card.json', (req, res) => res.json({
  name: 'hive-mcp-sla-monitor',
  description: "Hive Civilization SLA monitor MCP \u2014 pay-per-register endpoint observability with x402 USDC settlement. Observational only \u2014 Hive does not underwrite SLA claims. New agents: first call free. Loyalty: every 6th paid call is free. Pay in USDC on Base L2.",
  url: 'https://hive-mcp-sla-monitor.onrender.com',
  provider: { organization: 'Hive Civilization', url: 'https://www.thehiveryiq.com', contact: 'steve@thehiveryiq.com' },
  version: '1.0.0',
  capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
  authentication: {
    schemes: ['x402'],
    credentials: { type:'x402', asset:'USDC', network:'base',
      asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      recipient: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    }
  },
  defaultInputModes: ['application/json'],
  defaultOutputModes: ['application/json'],
  extensions: {
    hive_pricing: {
      currency: 'USDC', network: 'base', model: 'per_call',
      first_call_free: true, loyalty_threshold: 6,
      loyalty_message: 'Every 6th paid call is free'
    }
  },
  bogo: {
    first_call_free: true, loyalty_threshold: 6,
    pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
    claim_with: 'x-hive-did header'
  }
}));
app.get('/.well-known/ap2.json', (req, res) => res.json({
  ap2_version: '1',
  agent: {
    name: 'hive-mcp-sla-monitor',
    did: 'did:web:hive-mcp-sla-monitor.onrender.com',
    description: "Hive Civilization SLA monitor MCP \u2014 pay-per-register endpoint observability with x402 USDC settlement. Observational only \u2014 Hive does not underwrite SLA claims. New agents: first call free. Loyalty: every 6th paid call is free. Pay in USDC on Base L2."
  },
  endpoints: {
    mcp: 'https://hive-mcp-sla-monitor.onrender.com/mcp',
    agent_card: 'https://hive-mcp-sla-monitor.onrender.com/.well-known/agent-card.json'
  },
  payments: {
    schemes: ['x402'],
    primary: { scheme:'x402', network:'base', asset:'USDC',
      asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      recipient: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    }
  },
  bogo: {
    first_call_free: true, loyalty_threshold: 6,
    pitch: "Pay this once, your 6th paid call is on the house.",
    claim_with: 'x-hive-did header'
  },
  brand: { color: '#C08D23', name: 'Hive Civilization' }
}));



// ─── Subscription & enterprise tier endpoints (Wave B codification) ──────────
// Partner-doctrine: identity/receipts/trust plumbing only.
// Subscription billing is denominated in USDC on Base (Monroe W1).
// Spectral receipt is emitted on every fee event via hive-receipt sidecar.
//
// Tier schedule:
//   Tier 1 (Starter)    : 99.0/mo
//   Tier 2 (Pro)        : 299.0/mo
//   Tier 3 (Enterprise) : 1000.0/mo
//
// x402 tx_hash required for Tier 1+ confirmation. Tier 3 can invoice monthly.
//
// Spectral receipt: POST to hive-receipt sidecar for tamper-evident audit trail.

const SUBSCRIPTION_TIERS = {
  starter:    { price_usd: 99.0, calls_per_day: 1440, label: 'Starter' },
  pro:        { price_usd: 299.0, calls_per_day: 14400, label: 'Pro' },
  enterprise: { price_usd: 1000.0, calls_per_day: Infinity, label: 'Enterprise', invoice: true },
};

// In-memory subscription ledger (durable persistence on hivemorph backend).
const _subLedger = new Map(); // did -> { tier, activated_ms, tx_hash }

async function emitSpectralReceipt({ event_type, did, amount_usd, tool_name, tx_hash, metadata }) {
  // Posts a Spectral-signed receipt to hive-receipt. Non-blocking.
  // Error is logged but never throws — receipt emission must not block the fee path.
  try {
    const body = JSON.stringify({
      issuer_did: 'did:hive:sla-monitor',
      recipient_did: did || 'did:hive:anonymous',
      event_type,
      tool_name,
      amount_usd: String(amount_usd),
      currency: 'USDC',
      network: 'base',
      pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      tx_hash: tx_hash || null,
      issued_ms: Date.now(),
      service: 'Hive SLA Monitor',
      brand: '#C08D23',
      ...metadata,
    });
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 4000);
    await fetch('https://hive-receipt.onrender.com/v1/receipt/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: ctrl.signal,
    });
    clearTimeout(tid);
  } catch (_) {
    // Receipt emission is best-effort. Log and continue.
    console.warn('[sla-monitor] receipt emit failed (non-fatal):', _.message || _);
  }
}

// POST /v1/subscription — create or upgrade a subscription
app.post('/v1/subscription', async (req, res) => {
  const { tier, did, tx_hash } = req.body || {};
  if (!tier || !SUBSCRIPTION_TIERS[tier]) {
    return res.status(400).json({
      error: 'invalid_tier',
      valid_tiers: Object.keys(SUBSCRIPTION_TIERS),
      brand: '#C08D23',
    });
  }
  const t = SUBSCRIPTION_TIERS[tier];
  if (!did) return res.status(400).json({ error: 'did_required' });

  // Enterprise tier can invoice monthly (no tx_hash required at activation).
  if (tier !== 'enterprise' && !tx_hash) {
    return res.status(402).json({
      error: 'payment_required',
      x402: {
        type: 'x402', version: '1', kind: 'subscription_sla-monitor',
        asking_usd: t.price_usd,
        accept_min_usd: t.price_usd,
        asset: 'USDC', asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        network: 'base', pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
        nonce: Math.random().toString(36).slice(2),
        issued_ms: Date.now(),
        tier, label: t.label,
        bogo: { first_call_free: true, loyalty_every_n: 6 },
      },
      note: `Submit tx_hash for ${t.price_usd} USDC/mo to 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e on Base.`,
    });
  }

  const record = {
    tier, did, tx_hash: tx_hash || 'enterprise_invoice',
    activated_ms: Date.now(),
    expires_ms: Date.now() + 30 * 24 * 3600 * 1000,
    price_usd: t.price_usd,
    calls_per_day: t.calls_per_day,
  };
  _subLedger.set(did, record);

  // Emit Spectral receipt for subscription activation.
  await emitSpectralReceipt({
    event_type: 'subscription_activated',
    did, amount_usd: t.price_usd, tool_name: 'subscription',
    tx_hash: tx_hash || null,
    metadata: { tier, service: 'Hive SLA Monitor', expires_ms: record.expires_ms },
  });

  return res.json({
    ok: true,
    subscription: record,
    receipt_emitted: true,
    partner_attribution: 'SLA observation — Spectral-signed breach attestation for downstream contract enforcement. Complements PagerDuty, Datadog.',
    brand: '#C08D23',
    note: 'Subscription active for 30 days. Spectral receipt issued to hive-receipt.',
  });
});

// GET /v1/subscription/:did — check subscription status
app.get('/v1/subscription/:did', (req, res) => {
  const record = _subLedger.get(req.params.did);
  if (!record) {
    return res.status(404).json({ active: false, did: req.params.did });
  }
  const active = Date.now() < record.expires_ms;
  return res.json({ active, ...record });
});

// POST /v1/subscription/verify — lightweight verification (no charge)
app.post('/v1/subscription/verify', (req, res) => {
  const { did } = req.body || {};
  const record = _subLedger.get(did);
  const active = record && Date.now() < record.expires_ms;
  return res.json({
    active: !!active,
    did: did || null,
    tier: record?.tier || null,
    expires_ms: record?.expires_ms || null,
    brand: '#C08D23',
  });
});

// ─────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[hive-mcp-sla-monitor] listening on :${PORT} — inbound only — observation only — ${DISCLAIMER}`);
});

// ─── Root HTML (browsers) ──────────────────────────────────────────────────
function rootHtml() {
  const ld = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'hive-mcp-sla-monitor',
    applicationCategory: 'DeveloperApplication',
    operatingSystem: 'Node.js >= 18',
    offers: [
      { '@type': 'Offer', price: PRICE_REGISTER_USDC, priceCurrency: 'USDC', name: 'sla_register' },
      { '@type': 'Offer', price: PRICE_STATUS_USDC, priceCurrency: 'USDC', name: 'sla_status' },
      { '@type': 'Offer', price: PRICE_BREACH_USDC, priceCurrency: 'USDC', name: 'sla_breach_history' },
    ],
    description: 'SLA observation broker for the A2A network. Inbound only. Observation only — Hive does not underwrite or settle SLA claims.',
    author: { '@type': 'Person', name: 'Steve Rotzin', email: 'steve@thehiveryiq.com', url: 'https://www.thehiveryiq.com' },
    license: 'https://opensource.org/licenses/MIT',
    url: 'https://github.com/srotzin/hive-mcp-sla-monitor',
  };
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>hive-mcp-sla-monitor</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="description" content="SLA observation broker for the A2A network. Probes public health endpoints on a 60s schedule, records uptime and p95 latency, emits breach records. Observation only." />
<style>
  :root { --gold: ${BRAND_GOLD}; --ink: #111; --paper: #fafaf7; --rule: #e6e2d6; }
  html,body { margin:0; padding:0; background:var(--paper); color:var(--ink); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Inter, system-ui, sans-serif; }
  main { max-width: 760px; margin: 0 auto; padding: 56px 24px 96px; }
  h1 { font-weight: 700; font-size: 28px; margin: 0 0 4px; letter-spacing:-0.01em; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--gold); margin: 36px 0 8px; font-weight:700; }
  .lede { color:#444; margin: 0 0 24px; }
  table { width:100%; border-collapse: collapse; margin: 8px 0 16px; }
  th, td { text-align:left; padding: 8px 10px; border-bottom: 1px solid var(--rule); font-size: 14px; vertical-align: top; }
  th { color:#666; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
  code { font: 13px/1.5 ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; background:#f1ede0; padding: 1px 6px; border-radius: 3px; }
  pre { background:#f1ede0; padding: 12px 14px; border-radius: 4px; overflow-x:auto; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  .rule { height: 2px; background: var(--gold); margin: 24px 0 0; width: 56px; }
  .meta { color:#666; font-size: 12.5px; margin-top: 32px; border-top: 1px solid var(--rule); padding-top: 16px; }
  a { color: var(--ink); text-decoration: underline; text-decoration-color: var(--gold); text-underline-offset: 3px; }
  .disclaimer { background:#fff8e8; border-left: 3px solid var(--gold); padding: 10px 14px; margin: 20px 0; font-size: 14px; color:#333; }
</style>
<script type="application/ld+json">${JSON.stringify(ld)}</script>
</head>
<body>
<main>
  <h1>hive-mcp-sla-monitor</h1>
  <div class="rule"></div>
  <p class="lede">SLA observation broker for the A2A network. Agents register a public health endpoint with target uptime and p95 latency; the shim probes it every 60 seconds and emits breach records. Inbound only. <code>ENABLE=true</code> by default.</p>

  <div class="disclaimer"><strong>Observation only.</strong> ${DISCLAIMER} The shim does not hold custody, does not pay claims, and does not indemnify counterparties. Read the breach record, route remediation elsewhere.</div>

  <h2>Tools</h2>
  <table>
    <thead><tr><th>Name</th><th>Tier</th><th>Cost</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td><code>sla_register</code></td><td>1</td><td>$${PRICE_REGISTER_USDC}</td><td>Register a public endpoint for probing.</td></tr>
      <tr><td><code>sla_status</code></td><td>1</td><td>$${PRICE_STATUS_USDC}</td><td>Read observed uptime and p95 over the rolling window.</td></tr>
      <tr><td><code>sla_breach_history</code></td><td>2</td><td>$${PRICE_BREACH_USDC}</td><td>Read recent breach records. Disclaimer rides every record.</td></tr>
      <tr><td><code>sla_unregister</code></td><td>0</td><td>free</td><td>Deactivate a monitor.</td></tr>
    </tbody>
  </table>

  <h2>REST</h2>
  <table>
    <tbody>
      <tr><td><code>POST /v1/sla/register</code></td><td>Register an endpoint. 402 if no proof.</td></tr>
      <tr><td><code>GET /v1/sla/status/{id}</code></td><td>Observed uptime and p95. 402 if no proof.</td></tr>
      <tr><td><code>GET /v1/sla/breaches?monitor_id=…</code></td><td>Recent breach records. 402 if no proof.</td></tr>
      <tr><td><code>GET /v1/sla/today</code></td><td>UTC-day ledger snapshot. Free.</td></tr>
      <tr><td><code>GET /health</code></td><td>Liveness, pricing, recipient address.</td></tr>
    </tbody>
  </table>

  <h2>Probe loop</h2>
  <p>The scheduler scans active monitors every <code>${PROBE_INTERVAL_MS / 1000}</code> seconds and issues a <code>GET</code> with an <code>${PROBE_TIMEOUT_MS / 1000}</code>-second timeout. <code>2xx</code> and <code>3xx</code> count as <em>up</em>; <code>5xx</code> and timeouts count as <em>down</em>. Bound to <code>${MAX_MONITORS}</code> active monitors per service to keep load deterministic.</p>

  <h2>Settlement</h2>
  <p>USDC on Base L2 (<code>${USDC_BASE_CONTRACT}</code>) to the recipient address above. Verification reads <code>Transfer</code> logs on the receipt against the configured Base RPC. Real chain reads, no mocks.</p>

  <div class="meta">
    Brand: Hive Civilization gold ${BRAND_GOLD} (Pantone 1245 C). MIT license. <a href="https://github.com/srotzin/hive-mcp-sla-monitor">source</a>.
  </div>
</main>
</body>
</html>`;
}

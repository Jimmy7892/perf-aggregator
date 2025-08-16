import { Command } from 'commander';
import { readFileSync, existsSync } from 'fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'fs/promises';
import YAML from 'yaml';
import axios from 'axios';
import { canonicalize, sha256Hex } from './libs/canonical.js';
import { signEd25519Base64 } from './libs/crypto.js';
import { listenTrades, WsTrade } from './ws.js';

type Config = {
  backend: string;
  client_id: string;
  exchange: string;
  connector_version: string;
  mock_exchange_url?: string;
};

type MockTrade = {
  timestamp: string; // ISO
  price_usd: number;
  size_base: number;
  fee_usd: number;
};

function resolveConfigPath(p: string): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const base = path.basename(p);
  const candidates = [
    p,
    path.isAbsolute(p) ? p : path.resolve(p),
    path.join(process.cwd(), p),
    path.join(process.cwd(), base),
    path.join(__dirname, '..', base)
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  throw new Error(`Config not found. Tried: ${candidates.join(' | ')}`);
}

function loadConfig(p: string): Config {
  const resolved = resolveConfigPath(p);
  const txt = readFileSync(resolved, 'utf8');
  return YAML.parse(txt);
}

function bucketHour(tsIso: string): string {
  const d = new Date(tsIso);
  d.setUTCMinutes(0, 0, 0);
  return d.toISOString();
}

async function loadMockTrades(): Promise<MockTrade[]> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const candidates = [
    path.join(__dirname, '..', 'mock', 'trades.json'),
    path.join(__dirname, '..', 'src', 'mock', 'trades.json'),
    path.join(process.cwd(), 'services', 'connector', 'src', 'mock', 'trades.json'),
    path.join(process.cwd(), 'services', 'connector', 'mock', 'trades.json')
  ];
  for (const p of candidates) {
    try {
      const buf = await readFile(p);
      return JSON.parse(buf.toString());
    } catch {}
  }
  throw new Error(`Cannot load mock trades. Tried: ${candidates.join(' | ')}`);
}

function aggregateHourly(trades: MockTrade[]) {
  const byHour = new Map<string, MockTrade[]>();
  for (const t of trades) {
    const h = bucketHour(t.timestamp);
    const arr = byHour.get(h) ?? [];
    arr.push(t);
    byHour.set(h, arr);
  }
  const hours = Array.from(byHour.keys()).sort();
  let prevEnd = 0;
  const hourly_buckets = hours.map((h) => {
    const ts = byHour.get(h)!;
    ts.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const start = ts[0]?.price_usd || 0;
    const end = ts[ts.length - 1]?.price_usd || 0;
    const tradesCount = ts.length;
    const volume_base = ts.reduce((s, t) => s + t.size_base, 0);
    const volume_quote = ts.reduce((s, t) => s + t.size_base * t.price_usd, 0);
    const fees_usd = ts.reduce((s, t) => s + t.fee_usd, 0);
    const base = prevEnd || start;
    const ret = base === 0 ? 0 : (end - base) / base;
    prevEnd = end;
    return { t: h, start_usd: start, end_usd: end, return_pct: ret, trades: tradesCount, volume_base, volume_quote, fees_usd };
  });
  const totals = hourly_buckets.reduce(
    (acc, b) => {
      acc.trades += b.trades;
      acc.volume_base += b.volume_base;
      acc.volume_quote += b.volume_quote;
      acc.fees_usd += b.fees_usd;
      return acc;
    },
    { trades: 0, volume_base: 0, volume_quote: 0, fees_usd: 0 }
  );
  return { hourly_buckets, totals };
}

export async function runConnector(configPath: string, mock: boolean) {
  const cfg = loadConfig(configPath);
  const envKey = process.env.CONNECTOR_PRIVATE_KEY;
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const candidates = [
    envKey,
    path.join(process.cwd(), 'ed25519_private.key'),
    path.join(process.cwd(), 'services', 'connector', 'ed25519_private.key'),
    path.join(__dirname, '..', '..', 'ed25519_private.key'),
    path.join(__dirname, '..', 'ed25519_private.key')
  ].filter(Boolean) as string[];
  let selected: string | null = null;
  for (const p of candidates) {
    if (typeof p === 'string' && existsSync(p)) { selected = p; break; }
  }
  if (!selected) {
    console.error('Missing private key PEM. Tried:', candidates.join(' | '));
    process.exit(1);
  }
  const privatePem = readFileSync(selected, 'utf8');
  let trades: MockTrade[] = [];
  if (mock) {
    // If a mock exchange URL is provided, fetch from it, else use local file dataset
    const url = process.env.MOCK_EXCHANGE_URL || cfg.mock_exchange_url;
    if (url) {
      // Prefer websocket stream if available
      const wsUrl = process.env.MOCK_WS_URL || 'ws://localhost:4011/ws/trades';
      if (process.env.MOCK_USE_WS === '1') {
        const buffer: WsTrade[] = [];
        const stop = listenTrades(wsUrl, (t) => buffer.push(t));
        // collect for a short window
        await new Promise((r) => setTimeout(r, Number(process.env.MOCK_WINDOW_MS || 5000)));
        stop();
        trades = buffer.map((r) => ({ timestamp: new Date(r.ts).toISOString(), price_usd: r.price, size_base: r.size, fee_usd: r.fee }));
      } else {
        const res = await axios.get(`${url}/api/v1/market/trades`, { params: { symbol: 'BTCUSDT', limit: 100 } });
        const rows = res.data?.data || [];
        trades = rows.map((r: any) => ({ timestamp: new Date(r.ts).toISOString(), price_usd: Number(r.price), size_base: Number(r.size), fee_usd: Number(r.fee) }));
      }
    } else {
      // Use local dataset as fallback
      trades = await loadMockTrades();
    }
  }
  const period_start = trades.length ? trades[0]?.timestamp || new Date().toISOString() : new Date().toISOString();
  const period_end = trades.length ? trades[trades.length - 1]?.timestamp || new Date().toISOString() : new Date().toISOString();
  const { hourly_buckets, totals } = aggregateHourly(trades);
  const base = {
    client_id: cfg.client_id,
    exchange: cfg.exchange,
    connector_version: cfg.connector_version,
    period_start,
    period_end,
    hourly_buckets,
    totals,
    metadata: { mode: mock ? 'mock' : 'live' }
  } as const;

  const { signature: _skip, ...unsigned } = { ...base, signature: '' } as any;
  const canonical = canonicalize(unsigned);
  const signature = signEd25519Base64(canonical, privatePem);
  const payload = { ...base, signature };
  // Validate payload shape at runtime if libs exposes a zod schema in future.

  const canonicalWithSig = canonicalize(payload as any);
  const digest = sha256Hex(canonical);
  console.log('Payload digest:', digest);

  const backendOverride = process.env.CONNECTOR_BACKEND || cfg.backend;
  const url = `${backendOverride}/api/ingest`;
  const res = await axios.post(url, payload, { headers: { 'content-type': 'application/json' } });
  console.log('Ingest response:', res.status, res.data);
}

const program = new Command();
program
  .name('connector')
  .description('Track-record connector')
  .option('--mock', 'use mock dataset', false)
  .option('--daemon', 'run continuously (polling)', false)
  .option('--interval <seconds>', 'poll interval seconds (daemon)', (v) => Number(v), 10)
  .requiredOption('--config <path>', 'config file path')
  .action(async (opts) => {
    if (opts.daemon) {
      const intervalSec: number = opts.interval ?? 10;
      const maxIterations = Number(process.env.MAX_ITERATIONS || 0);
      let iter = 0;
      // initial immediate run
      await runConnector(opts.config, opts.mock);
      // loop
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (maxIterations && iter >= maxIterations) break;
        await new Promise((r) => setTimeout(r, intervalSec * 1000));
        await runConnector(opts.config, opts.mock);
        iter++;
      }
      return;
    }
    await runConnector(opts.config, opts.mock);
  });

program.parseAsync();


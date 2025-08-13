import Fastify, { FastifyReply, FastifyRequest } from "fastify";
import { WebSocketServer } from "ws";
import { createHash, randomBytes } from "crypto";
import { existsSync, readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import { canonicalize } from "./libs/canonical.js";
import { signEd25519Base64, decryptRsaOaepJson, hmacSha256Hex } from "./libs/crypto.js";
import { ExchangeConnector, UserConfig, UserTrade } from "./exchange-connector.js";
import { TradeAggregator, MinuteAggregation } from "./trade-aggregator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TradeData {
  symbol: string;
  price: number;
  size: number;
  side: "buy" | "sell";
  timestamp: number;
  fee: number;
}

interface HourBucketT {
  symbol: string;
  hour_utc: string;
  start_usd: number;
  end_usd: number;
  trades_count: number;
  volume_usd: number;
  volume_base: number;
  volume_quote: number;
  fees_usd: number;
  trades: TradeData[];
  [key: string]: any;
}

interface AggregationJob {
  id: string;
  startTime: number;
  trades: TradeData[];
  status: "collecting" | "processing" | "completed" | "failed";
  result?: any;
}

class AggregationService {
  private jobs = new Map<string, AggregationJob>();
  public backendUrl: string;
  public privateKey: string;
  private exchangeConnector: ExchangeConnector;
  public tradeAggregator: TradeAggregator;

  constructor() {
    this.backendUrl = process.env.AGGREGATOR_BACKEND_URL || "http://localhost:3010";
    this.privateKey = this.loadPrivateKey();
    this.exchangeConnector = new ExchangeConnector();
    this.tradeAggregator = new TradeAggregator();
    
    // Écouter les trades des exchanges
    this.exchangeConnector.on('trade', (trade: UserTrade) => {
      this.tradeAggregator.processTrade(trade);
      console.log(`📊 Trade traité: ${trade.userId} ${trade.symbol} ${trade.side} ${trade.amount}`);
    });
  }

  enrollEncryptedClient(encryptedEnvelopeB64: string): { clientId: string } {
    // Decrypt in RAM-only; envelope contains { exchange, apiKey, secret, symbols? }
    const privPem = this.privateKey; // Reuse ED25519? For RSA-OAEP, mount an RSA key instead
    // In production, use a dedicated RSA private key; here assume ED25519 not compatible with RSA-OAEP.
    // So prefer environment variable AGGREGATOR_RSA_PRIVATE_KEY
    const rsaPem = process.env.AGGREGATOR_RSA_PRIVATE_KEY;
    if (!rsaPem) throw new Error("Missing AGGREGATOR_RSA_PRIVATE_KEY for enrollment");
    const payload = decryptRsaOaepJson<any>(encryptedEnvelopeB64, rsaPem);
    if (!payload?.exchange || !payload?.apiKey || !payload?.secret) {
      throw new Error("Invalid envelope");
    }
    // Derive pseudonymous clientId
    const salt = process.env.AGGREGATOR_CLIENT_SALT || "default_salt_change_me";
    const apiKeyId = payload.apiKey.slice(0, 6) + "..." + payload.apiKey.slice(-4);
    const clientId = hmacSha256Hex(salt, `${payload.exchange}:${apiKeyId}`);
    // Register to connector
    this.addUser({
      userId: clientId,
      exchange: payload.exchange,
      apiKey: payload.apiKey,
      secret: payload.secret,
      sandbox: !!payload.sandbox,
      symbols: payload.symbols || ["BTC/USDT", "ETH/USDT"],
    });
    return { clientId };
  }

  private loadPrivateKey(): string {
    const candidates = [
      process.env.AGGREGATOR_PRIVATE_KEY,
      path.resolve("ed25519_private.key"),
      path.join(__dirname, "..", "ed25519_private.key"),
    ].filter(Boolean) as string[];

    for (const keyPath of candidates) {
      if (existsSync(keyPath)) {
        return readFileSync(keyPath, "utf8");
      }
    }
    throw new Error(`Private key not found. Tried: ${candidates.join(", ")}`);
  }

  createJob(): string {
    const id = randomBytes(16).toString("hex");
    const job: AggregationJob = {
      id,
      startTime: Date.now(),
      trades: [],
      status: "collecting"
    };
    this.jobs.set(id, job);
    
    // Auto-cleanup after 10 minutes
    setTimeout(() => {
      this.jobs.delete(id);
    }, 10 * 60 * 1000);

    return id;
  }

  addTrade(jobId: string, trade: TradeData): boolean {
    const job = this.jobs.get(jobId);
    if (!job || job.status !== "collecting") {
      return false;
    }
    
    job.trades.push(trade);
    console.log(`Job ${jobId}: Added trade ${trade.symbol} ${trade.price} ${trade.size}`);
    return true;
  }

  async processJob(jobId: string): Promise<any> {
    const job = this.jobs.get(jobId);
    if (!job || job.status !== "collecting") {
      throw new Error(`Job ${jobId} not found or not in collecting state`);
    }

    job.status = "processing";
    console.log(`Processing job ${jobId} with ${job.trades.length} trades`);

    try {
      // Calculate hourly aggregates
      const buckets = this.aggregateTradesByHour(job.trades);
      
      // Create payload
      const now = new Date().toISOString();
      const payload = {
        client_id: "test-client-1",
        exchange: "mock",
        connector_version: "0.2.0",
        period_start: now,
        period_end: now,
        hourly_buckets: buckets.map(b => {
          // Ne pas inclure de champs de trades individuels
          const { fees_usd, trades, return_pct, volume_base, volume_quote } = b as any;
          return { t: b.t, return_pct, trades, volume_base, volume_quote, fees_usd };
        }),
        totals: {
          trades: buckets.reduce((sum, b) => sum + (b as any).trades, 0),
          volume_base: buckets.reduce((sum, b) => sum + (b as any).volume_base, 0),
          volume_quote: buckets.reduce((sum, b) => sum + (b as any).volume_quote, 0),
          fees_usd: buckets.reduce((sum, b) => sum + b.fees_usd, 0)
        }
      };

      // Canonicalize and sign (without signature field, like backend does)
      const canonical = canonicalize(payload);
      const signature = signEd25519Base64(canonical, this.privateKey);
      const digest = createHash("sha256").update(canonical).digest("hex");

      // Embed signature and send to backend (payload must match IngestPayload schema)
      (payload as any).signature = signature;
      const response = await axios.post(`${this.backendUrl}/api/ingest`, payload, {
        headers: { "Content-Type": "application/json" },
        timeout: 30000
      });

      job.status = "completed";
      job.result = {
        digest,
        backend_response: response.data,
        buckets_count: buckets.length,
        trades_processed: job.trades.length
      };

      console.log(`Job ${jobId} completed: ${job.result.buckets_count} buckets, digest ${digest.slice(0, 8)}...`);
      return job.result;

    } catch (error: any) {
      job.status = "failed";
      const errMsg = error instanceof Error ? error.message : String(error);
      const errData = error?.response?.data ?? null;
      job.result = { error: errMsg, backend_error: errData } as any;
      console.error(`Job ${jobId} failed:`, errMsg, errData ? JSON.stringify(errData) : "");
      throw error;
    }
  }

  private aggregateTradesByHour(trades: TradeData[]): HourBucketT[] {
    const hourlyMap = new Map<string, {
      symbol: string;
      hour_utc: string;
      start_usd: number;
      end_usd: number;
      trades_count: number;
      volume_usd: number;
      volume_base: number;
      volume_quote: number;
      fees_usd: number;
      trades: TradeData[];
    }>();

    // Group trades by symbol and hour
    for (const trade of trades) {
      const hourKey = new Date(trade.timestamp).toISOString().slice(0, 13) + ":00:00.000Z";
      const key = `${trade.symbol}-${hourKey}`;
      
      if (!hourlyMap.has(key)) {
        hourlyMap.set(key, {
          symbol: trade.symbol,
          hour_utc: hourKey,
          start_usd: trade.price,
          end_usd: trade.price,
          trades_count: 0,
          volume_usd: 0,
          volume_base: 0,
          volume_quote: 0,
          fees_usd: 0,
          trades: []
        });
      }

      const bucket = hourlyMap.get(key)!;
      bucket.trades.push(trade);
      bucket.trades_count++;
      bucket.volume_usd += trade.price * trade.size;
      bucket.volume_base += trade.size;
      bucket.volume_quote += trade.price * trade.size;
      bucket.fees_usd += trade.fee;
      bucket.end_usd = trade.price; // Last trade price
    }

    // Convert to final format
    return Array.from(hourlyMap.values()).map(bucket => {
      // Sort trades by timestamp to get proper start/end prices
      bucket.trades.sort((a, b) => a.timestamp - b.timestamp);
      const startPrice = bucket.trades[0].price;
      const endPrice = bucket.trades[bucket.trades.length - 1].price;
      
      // Ne pas exposer directement start/end price
      return {
        t: bucket.hour_utc,
        return_pct: ((endPrice - startPrice) / startPrice) * 100,
        trades: bucket.trades_count,
        volume_base: bucket.volume_base,
        volume_quote: bucket.volume_quote,
        fees_usd: bucket.fees_usd
      } as any;
    });
  }

  getJobStatus(jobId: string): AggregationJob | null {
    return this.jobs.get(jobId) || null;
  }

  addUser(config: UserConfig): void {
    this.exchangeConnector.addUser(config);
  }

  removeUser(userId: string): void {
    this.exchangeConnector.removeUser(userId);
  }

  getUserAggregations(userId: string): MinuteAggregation[] {
    return this.tradeAggregator.getMinuteAggregations().filter(agg => agg.userId === userId);
  }

  async startExchangeConnector(): Promise<void> {
    await this.exchangeConnector.start();
  }

  stopExchangeConnector(): void {
    this.exchangeConnector.stop();
  }
}

// Initialize service
const aggregationService = new AggregationService();
const app = Fastify({ logger: { level: "info" } });

// Health check
app.get("/health", async (request, reply) => {
  return { status: "ok", timestamp: new Date().toISOString() };
});

// Create new aggregation job
app.post("/jobs", async (request, reply) => {
  const jobId = aggregationService.createJob();
  return { job_id: jobId, ws_url: `ws://localhost:${process.env.AGGREGATOR_WS_PORT || 5010}/ws/${jobId}` };
});

// Get job status
app.get("/jobs/:jobId", async (request: FastifyRequest<{ Params: { jobId: string } }>, reply) => {
  const job = aggregationService.getJobStatus(request.params.jobId);
  if (!job) {
    return reply.code(404).send({ error: "Job not found" });
  }
  return {
    job_id: job.id,
    status: job.status,
    trades_count: job.trades.length,
    result: job.result
  };
});

// Ajouter un utilisateur pour surveiller ses trades
app.post("/users", async (request: FastifyRequest<{ Body: UserConfig }>, reply) => {
  try {
    aggregationService.addUser(request.body);
    return { success: true, message: "Utilisateur ajouté" };
  } catch (error) {
    return reply.code(400).send({ error: error instanceof Error ? error.message : String(error) });
  }
});

// Supprimer un utilisateur
app.delete("/users/:userId", async (request: FastifyRequest<{ Params: { userId: string } }>, reply) => {
  aggregationService.removeUser(request.params.userId);
  return { success: true, message: "Utilisateur supprimé" };
});

// Obtenir les agrégations par minute d'un utilisateur
app.get("/users/:userId/aggregations", async (request: FastifyRequest<{ Params: { userId: string } }>, reply) => {
  const aggregations = aggregationService.getUserAggregations(request.params.userId);
  return { aggregations };
});

// Enrollment stateless: reçoit une enveloppe chiffrée (RSA-OAEP b64), renvoie un clientId pseudonyme
app.post("/enroll", async (request: FastifyRequest<{ Body: { envelope_b64: string } }>, reply) => {
  try {
    const body: any = request.body || {};
    if (!body.envelope_b64) return reply.code(400).send({ error: "Missing envelope_b64" });
    const res = aggregationService.enrollEncryptedClient(body.envelope_b64);
    return res;
  } catch (e) {
    return reply.code(400).send({ error: e instanceof Error ? e.message : String(e) });
  }
});

// Process job (finalize aggregation)
app.post("/jobs/:jobId/process", async (request: FastifyRequest<{ Params: { jobId: string } }>, reply) => {
  try {
    const result = await aggregationService.processJob(request.params.jobId);
    return result;
  } catch (error) {
    return reply.code(400).send({ 
      error: error instanceof Error ? error.message : String(error) 
    });
  }
});

// Start HTTP server
const httpPort = Number(process.env.AGGREGATOR_PORT || 5000);
app.listen({ port: httpPort, host: "0.0.0.0" }).then(async () => {
  console.log(`Aggregator HTTP listening on http://localhost:${httpPort}`);
  
  // Start WebSocket server
  const wsPort = Number(process.env.AGGREGATOR_WS_PORT || 5010);
  const wss = new WebSocketServer({ port: wsPort });
  console.log(`Aggregator WebSocket listening on ws://localhost:${wsPort}`);

  // Démarrer le connecteur d'exchanges
  await aggregationService.startExchangeConnector();
  
  // Envoyer les agrégations au backend toutes les minutes
  const sendAggregationsInterval = setInterval(async () => {
    try {
      const aggregations = aggregationService.tradeAggregator.getMinuteAggregations(new Date(Date.now() - 60000));
      
      if (aggregations.length > 0) {
        for (const agg of aggregations) {
            const payload = {
              client_id: "test-client-1",
            exchange: "live",
            connector_version: "0.2.0",
            period_start: agg.timestamp,
            period_end: agg.timestamp,
            hourly_buckets: [{
              t: agg.timestamp,
              return_pct: agg.returnPct,
              trades: agg.tradesCount,
              volume_base: agg.volume,
              volume_quote: agg.volume,
              fees_usd: agg.fees
            }],
            totals: {
              trades: agg.tradesCount,
              volume_base: agg.volume,
              volume_quote: agg.volume,
              fees_usd: agg.fees
            },
          };

          const canonical = canonicalize(payload);
          const signature = signEd25519Base64(canonical, aggregationService.privateKey);
          const digest = createHash("sha256").update(canonical).digest("hex");

          (payload as any).signature = signature;
          const response = await axios.post(`${aggregationService.backendUrl}/api/ingest`, payload, {
            headers: { "Content-Type": "application/json" },
            timeout: 30000
          });

          console.log(`📤 Agrégation envoyée pour ${agg.userId}: ${agg.returnPct.toFixed(2)}% return`);
        }
      }
    } catch (error) {
      console.error('❌ Erreur envoi agrégations:', error);
    }
  }, 60000); // Toutes les minutes

  // Graceful shutdown
  const shutdown = () => {
    console.log('🛑 Arrêt du service...');
    clearInterval(sendAggregationsInterval);
    aggregationService.stopExchangeConnector();
    process.exit(0);
  };
  
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  wss.on("connection", (ws, req) => {
    const url = req.url || "/";
    const jobMatch = url.match(/^\/ws\/([a-f0-9]+)$/);
    
    if (!jobMatch) {
      ws.close(1008, "Invalid WebSocket path. Use /ws/{jobId}");
      return;
    }

    const jobId = jobMatch[1];
    const job = aggregationService.getJobStatus(jobId);
    
    if (!job) {
      ws.close(1008, "Job not found");
      return;
    }

    console.log(`WebSocket connected for job ${jobId}`);
    
    ws.on("message", (data) => {
      try {
        const message = JSON.parse(data.toString());
        
        if (message.type === "trade" && message.data) {
          const trade = message.data as TradeData;
          
          // Validate required fields
          if (!trade.symbol || typeof trade.price !== "number" || 
              typeof trade.size !== "number" || !trade.side || 
              typeof trade.timestamp !== "number") {
            ws.send(JSON.stringify({ 
              type: "error", 
              message: "Invalid trade data format" 
            }));
            return;
          }

          const success = aggregationService.addTrade(jobId, trade);
          if (success) {
            ws.send(JSON.stringify({ 
              type: "ack", 
              trade_id: `${trade.symbol}-${trade.timestamp}` 
            }));
          } else {
            ws.send(JSON.stringify({ 
              type: "error", 
              message: "Job not in collecting state" 
            }));
          }
        } else {
          ws.send(JSON.stringify({ 
            type: "error", 
            message: "Unknown message type" 
          }));
        }
      } catch (error) {
        ws.send(JSON.stringify({ 
          type: "error", 
          message: "Invalid JSON format" 
        }));
      }
    });

    ws.on("close", () => {
      console.log(`WebSocket disconnected for job ${jobId}`);
    });

    ws.on("error", (error) => {
      console.error(`WebSocket error for job ${jobId}:`, error);
    });

    // Send welcome message
    ws.send(JSON.stringify({ 
      type: "welcome", 
      job_id: jobId,
      message: "Send trade data as JSON: {type: 'trade', data: {symbol, price, size, side, timestamp, fee}}" 
    }));
  });
});

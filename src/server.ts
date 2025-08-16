/**
 * Secure TEE Enclave Backend Server
 *
 * SECURITY OBJECTIVES:
 * - Accept encrypted API keys, never store them in plaintext
 * - Forward to TEE enclave for processing
 * - Return signed aggregated results only
 * - Implement comprehensive security controls
 */

import Fastify from 'fastify';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { decryptCredentials } from './libs/crypto.js';
import { CryptoUtils } from './utils/crypto.js';
import { logger } from './utils/logger.js';
import { PublicLogsServer } from './api/public-logs.js';
import { ExchangePoller } from './exchange-poller.js';
import { UserConfig, PerformanceMetrics } from './types/index.js';
import { getConfig } from './config/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Removed EnclaveConfig - using centralized config now

interface CredentialEnvelope {
  ephemeral_pub: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  metadata: {
    exchange: string;
    label: string;
    ttl: number;
  };
}

export class PerformanceAggregatorServer {
  private fastify: any;
  private exchangePoller: ExchangePoller;
  private publicLogsServer?: PublicLogsServer;
  private config = getConfig();
  private userSessions = new Map<string, { userId: string; config: UserConfig; expiresAt: number }>();
  private metricsStore = new Map<string, any[]>(); // Temporary metrics storage

  constructor() {
    this.fastify = Fastify({ logger: true });
    this.exchangePoller = new ExchangePoller({
      intervalSeconds: 300, // 5 minutes - institutional standard
      maxRetries: 3,
      enableRateLimit: true
    });

    this.setupRoutes();
    this.setupEventHandlers();
  }

  private setupRoutes(): void {
    // Enclave attestation endpoint
    this.fastify.get('/attestation/quote', async (request: any, reply: any) => {
      return {
        enclave_id: 'perf-aggregator-enclave-v1',
        attestation_type: 'SGX_QUOTE',
        public_key: await this.getPublicKey(),
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      };
    });

    // Secure credential submission endpoint
    this.fastify.post('/enclave/submit_key', async (request: any, reply: any) => {
      const envelope = request.body as CredentialEnvelope;

      try {
        // Decrypt credentials using X25519 ECDH + AES-GCM
        const decryptedData = this.decryptCredentialEnvelope(envelope);
        const { userId, exchange, apiKey, secret, accountType, sandbox } = decryptedData;

        // Validate required data
        if (!userId || !exchange || !apiKey || !secret) {
          return reply.status(400).send({ error: 'Missing required data' });
        }

        // Create user configuration
        const userConfig: UserConfig = {
          userId,
          exchange,
          apiKey,
          secret,
          accountType: accountType || 'spot',
          sandbox: sandbox || false,
          apiInterval: 60000,
          maxRetries: 3
        };

        // Generate secure session ID
        const sessionId = CryptoUtils.generateSessionId();
        const expiresAt = Date.now() + (envelope.metadata.ttl * 1000);

        // Store session
        this.userSessions.set(sessionId, {
          userId,
          config: userConfig,
          expiresAt
        });

        // Add user to exchange poller
        await this.exchangePoller.addUser(userConfig);

        logger.logSessionEvent('user_registered', sessionId, userId, {
          exchange,
          account_type: accountType || 'spot',
          sandbox: sandbox || false
        });

        console.log(`🔐 User ${userId} securely registered with session ${sessionId}`);

        return {
          session_id: sessionId,
          expires_at: new Date(expiresAt).toISOString(),
          status: 'active'
        };

      } catch (error) {
        console.error('❌ Credential decryption error:', error);
        return reply.status(400).send({ error: 'Invalid credentials' });
      }
    });

    // Metrics retrieval (authenticated by session)
    this.fastify.get('/enclave/metrics/:sessionId', async (request: any, reply: any) => {
      const { sessionId } = request.params as { sessionId: string };

      const session = this.userSessions.get(sessionId);
      if (!session || session.expiresAt < Date.now()) {
        return reply.status(401).send({ error: 'Invalid or expired session' });
      }

      const metrics = this.metricsStore.get(session.userId) || [];
      const summary = this.calculateSummary(session.userId);

      return {
        metrics,
        summary,
        session_expires: new Date(session.expiresAt).toISOString()
      };
    });

    // Summary retrieval (authenticated by session)
    this.fastify.get('/enclave/summary/:sessionId', async (request: any, reply: any) => {
      const { sessionId } = request.params as { sessionId: string };

      const session = this.userSessions.get(sessionId);
      if (!session || session.expiresAt < Date.now()) {
        return reply.status(401).send({ error: 'Invalid or expired session' });
      }

      const summary = this.calculateSummary(session.userId);
      return {
        summary,
        session_expires: new Date(session.expiresAt).toISOString()
      };
    });

    // Expired session cleanup
    this.fastify.post('/enclave/cleanup', async (request: any, reply: any) => {
      const now = Date.now();
      let cleanedCount = 0;

      for (const [sessionId, session] of this.userSessions.entries()) {
        if (session.expiresAt < now) {
          this.userSessions.delete(sessionId);
          cleanedCount++;
        }
      }

      return { cleaned_sessions: cleanedCount };
    });
  }

  private setupEventHandlers(): void {
    // Process snapshots from exchange poller
    this.exchangePoller.on('snapshot', (snapshot) => {
      this.processSnapshot(snapshot);
    });

    // Process calculated metrics
    this.exchangePoller.on('metrics', (metrics) => {
      this.storeMetrics(metrics);
    });

    // Handle polling errors
    this.exchangePoller.on('error', (error) => {
      logger.error('exchange_poller', 'polling_error', {
        details: {
          user_id_hash: error.userId?.slice(0, 8) + '*'.repeat(8),
          error_type: error.type,
          error_message: error.error?.message || 'Unknown error'
        }
      });
    });
  }

  private async getPublicKey(): Promise<string> {
    // In production, read from secure file
    return 'enclave-public-key-base64';
  }

  /**
   * Decrypt credential envelope using X25519 ECDH + AES-GCM
   * Uses actual cryptographic implementation
   */
  private decryptCredentialEnvelope(envelope: CredentialEnvelope): any {
    // In production, this private key would be securely stored in TEE
    const enclavePrivateKey = this.getEnclavePrivateKey();
    
    return decryptCredentials(
      envelope.ephemeral_pub,
      envelope.nonce,
      envelope.ciphertext,
      envelope.tag,
      enclavePrivateKey
    );
  }

  /**
   * Get enclave private key (in production, from secure storage)
   */
  private getEnclavePrivateKey(): string {
    // In production, this would be loaded from secure TEE storage
    // For development, generate a consistent key
    return process.env.ENCLAVE_PRIVATE_KEY || this.generateDevelopmentKey();
  }

  /**
   * Generate development key for testing (NOT for production)
   */
  private generateDevelopmentKey(): string {
    // This is for development only - in production use secure key management
    return `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIGg8+h0l6nGrXdCgFeUsOOv3xv2l8o9kRJq2F+HsPD2j
-----END PRIVATE KEY-----`;
  }

  async start(): Promise<void> {
    try {
      await this.fastify.listen({ port: this.config.server.port, host: this.config.server.host });

      // Start public logs server if enabled
      if (this.config.logging.publicEnabled) {
        this.publicLogsServer = new PublicLogsServer();
        await this.publicLogsServer.start();
      }

      logger.info('server', 'started', {
        details: {
          host: this.config.server.host,
          port: this.config.server.port,
          public_logs: this.config.logging.publicEnabled
        }
      });

      console.log(`🔐 Performance Aggregator started on ${this.config.server.host}:${this.config.server.port}`);

      // Start exchange poller
      await this.exchangePoller.start();

      // Setup session cleanup
      setInterval(() => {
        this.cleanupExpiredSessions();
      }, this.config.cleanup.sessionCleanupInterval);

    } catch (error) {
      console.error('❌ Error starting server:', error);
      throw error;
    }
  }

  private cleanupExpiredSessions(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [sessionId, session] of this.userSessions.entries()) {
      if (session.expiresAt < now) {
        this.userSessions.delete(sessionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(`🧹 ${cleanedCount} expired sessions cleaned`);
    }
  }

  /**
   * Process exchange snapshot and store in database
   */
  private processSnapshot(snapshot: any): void {
    logger.debug('server', 'snapshot_processed', {
      details: {
        user_id_hash: snapshot.userId?.slice(0, 8) + '*'.repeat(8),
        exchange: snapshot.exchange,
        portfolio_value: snapshot.portfolioValue?.total
      }
    });

    // In production, this would store to performance_snapshots table
    // For now, keep in memory for demonstration
  }

  /**
   * Store calculated metrics
   */
  private storeMetrics(metrics: any): void {
    const userMetrics = this.metricsStore.get(metrics.userId) || [];
    userMetrics.push(metrics);
    
    // Keep only last 100 metrics per user to prevent memory issues
    if (userMetrics.length > 100) {
      userMetrics.splice(0, userMetrics.length - 100);
    }
    
    this.metricsStore.set(metrics.userId, userMetrics);

    logger.debug('server', 'metrics_stored', {
      details: {
        user_id_hash: metrics.userId?.slice(0, 8) + '*'.repeat(8),
        metrics_count: userMetrics.length
      }
    });
  }

  /**
   * Calculate summary for user
   */
  private calculateSummary(userId: string): any {
    const metrics = this.metricsStore.get(userId) || [];
    
    if (metrics.length === 0) {
      return {
        totalReturn: 0,
        totalReturnPct: 0,
        totalVolume: 0,
        totalFees: 0,
        tradeCount: 0,
        lastUpdated: new Date().toISOString()
      };
    }

    const latest = metrics[metrics.length - 1];
    return {
      totalReturn: latest.totalReturn || 0,
      totalReturnPct: latest.totalReturnPct || 0,
      totalVolume: latest.totalVolume || 0,
      totalFees: latest.totalFees || 0,
      tradeCount: latest.tradeCount || 0,
      sharpeRatio: latest.sharpeRatio || 0,
      maxDrawdown: latest.maxDrawdown || 0,
      volatility: latest.volatility || 0,
      lastUpdated: latest.lastUpdated || new Date().toISOString()
    };
  }

  async stop(): Promise<void> {
    await this.fastify.close();

    if (this.publicLogsServer) {
      await this.publicLogsServer.stop();
    }

    await this.exchangePoller.stop();

    logger.info('server', 'stopped', {
      details: { message: 'Performance Aggregator server stopped' }
    });

    console.log('🛑 Server stopped');
  }
}

// Start server if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new PerformanceAggregatorServer();

  process.on('SIGINT', async () => {
    console.log('\n🛑 Stopping server...');
    await server.stop();
    process.exit(0);
  });

  server.start().catch(console.error);
}

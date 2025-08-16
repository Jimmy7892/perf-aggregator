/**
 * Secure TEE Enclave Backend Server
 *
 * SECURITY OBJECTIVES:
 * - Accept encrypted API keys, never store them in plaintext
 * - Forward to TEE enclave for processing
 * - Return signed aggregated results only
 * - Implement comprehensive security controls
 */

import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { decryptCredentials } from './libs/crypto.js';
import { CryptoUtils } from './utils/crypto.js';
import { logger } from './utils/logger.js';
import { PublicLogsServer } from './api/public-logs.js';
import { ExchangePoller, ExchangeSnapshot, AggregatedMetrics } from './exchange-poller.js';
import { UserConfig, PerformanceMetrics } from './types/index.js';
import { getConfig } from './config/index.js';
import { DatabaseService, UserSession } from './services/database.js';

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


interface PollingError {
  userId: string;
  error: Error;
  type: string;
}

interface MetricsSummary {
  totalReturn: number;
  totalReturnPct: number;
  totalVolume: number;
  totalFees: number;
  tradeCount: number;
  sharpeRatio?: number;
  maxDrawdown?: number;
  volatility?: number;
  lastUpdated: string;
}

export class PerformanceAggregatorServer {
  private fastify: FastifyInstance;
  private exchangePoller: ExchangePoller;
  private publicLogsServer?: PublicLogsServer;
  private config = getConfig();
  private database: DatabaseService;

  constructor() {
    this.fastify = Fastify({ logger: true });
    this.exchangePoller = new ExchangePoller({
      intervalSeconds: 300, // 5 minutes - institutional standard
      maxRetries: 3,
      enableRateLimit: true
    });
    this.database = new DatabaseService({
      // Configuration from environment variables
      connectionString: process.env.DATABASE_URL,
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'perf_aggregator',
      username: process.env.DB_USER || 'app_service',
      password: process.env.DB_PASSWORD,
      ssl: process.env.DB_SSL === 'true',
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10')
    });

    this.setupRoutes();
    this.setupEventHandlers();
  }

  private setupRoutes(): void {
    // Enclave attestation endpoint
    this.fastify.get('/attestation/quote', async (request: FastifyRequest, reply: FastifyReply) => {
      return {
        enclave_id: 'perf-aggregator-enclave-v1',
        attestation_type: 'SGX_QUOTE',
        public_key: await this.getPublicKey(),
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      };
    });

    // Secure credential submission endpoint
    this.fastify.post<{ Body: CredentialEnvelope }>('/enclave/submit_key', async (request: FastifyRequest<{ Body: CredentialEnvelope }>, reply: FastifyReply) => {
      const envelope = request.body;

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

        // Store session in database
        const session: UserSession = {
          id: sessionId,
          userId,
          config: userConfig,
          expiresAt,
          createdAt: new Date()
        };
        await this.database.storeSession(session);

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
    this.fastify.get<{ Params: { sessionId: string } }>('/enclave/metrics/:sessionId', async (request: FastifyRequest<{ Params: { sessionId: string } }>, reply: FastifyReply) => {
      const { sessionId } = request.params;

      const session = await this.database.getSession(sessionId);
      if (!session) {
        return reply.status(401).send({ error: 'Invalid or expired session' });
      }

      const metrics = await this.database.getMetrics(sessionId);

      return {
        metrics,
        session_expires: new Date(session.expiresAt).toISOString()
      };
    });



    // Expired session cleanup
    this.fastify.post('/enclave/cleanup', async (request: FastifyRequest, reply: FastifyReply) => {
      const cleanedCount = await this.database.cleanupExpiredSessions();
      return { cleaned_sessions: cleanedCount };
    });
  }

  private setupEventHandlers(): void {
    // Process snapshots from exchange poller
    this.exchangePoller.on('snapshot', async (snapshot) => {
      await this.processSnapshot(snapshot);
    });

    // Process calculated metrics
    this.exchangePoller.on('metrics', async (metrics) => {
      await this.storeMetrics(metrics);
    });

    // Handle polling errors
    this.exchangePoller.on('error', (error: PollingError) => {
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
  private decryptCredentialEnvelope(envelope: CredentialEnvelope): { 
    userId: string; 
    exchange: string; 
    apiKey: string; 
    secret: string; 
    accountType?: string; 
    sandbox?: boolean; 
  } {
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
      // Initialize database first
      await this.database.initialize();

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
          public_logs: this.config.logging.publicEnabled,
          database: this.database.getStats()
        }
      });

      console.log(`🔐 Performance Aggregator started on ${this.config.server.host}:${this.config.server.port}`);
      console.log(`💾 Database: ${this.database.getStats().isConnected ? 'Connected' : 'In-memory fallback'}`);

      // Start exchange poller
      await this.exchangePoller.start();

      // Setup session cleanup
      setInterval(async () => {
        await this.cleanupExpiredSessions();
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
  private async processSnapshot(snapshot: ExchangeSnapshot): Promise<void> {
    if (!snapshot || !snapshot.userId) {
      logger.warn('server', 'invalid_snapshot', { details: { reason: 'Missing userId or snapshot' } });
      return;
    }

    try {
      // Find session ID for this user
      const sessionId = await this.findSessionIdForUser(snapshot.userId);
      if (!sessionId) {
        logger.warn('server', 'no_session_for_snapshot', { 
          details: { user_id_hash: snapshot.userId.slice(0, 8) + '*'.repeat(8) } 
        });
        return;
      }

      // Store snapshot in database
      await this.database.storeSnapshot(sessionId, snapshot);

      logger.debug('server', 'snapshot_processed', {
        details: {
          user_id_hash: snapshot.userId.slice(0, 8) + '*'.repeat(8),
          exchange: snapshot.exchange,
          portfolio_value: snapshot.portfolioValue?.total
        }
      });
    } catch (error) {
      logger.error('server', 'snapshot_processing_failed', {
        details: {
          user_id_hash: snapshot.userId.slice(0, 8) + '*'.repeat(8),
          error: error instanceof Error ? error.message : String(error)
        }
      });
    }
  }

  /**
   * Store calculated metrics
   */
  private async storeMetrics(metrics: AggregatedMetrics): Promise<void> {
    if (!metrics || !metrics.userId) {
      logger.warn('server', 'invalid_metrics', { details: { reason: 'Missing userId or metrics' } });
      return;
    }

    try {
      // Find session ID for this user
      const sessionId = await this.findSessionIdForUser(metrics.userId);
      if (!sessionId) {
        logger.warn('server', 'no_session_for_metrics', { 
          details: { user_id_hash: metrics.userId.slice(0, 8) + '*'.repeat(8) } 
        });
        return;
      }

      // Store metrics in database
      await this.database.storeMetrics(sessionId, metrics);

      logger.debug('server', 'metrics_stored', {
        details: {
          user_id_hash: metrics.userId.slice(0, 8) + '*'.repeat(8),
          return_pct: metrics.totalReturnPct
        }
      });
    } catch (error) {
      logger.error('server', 'metrics_storage_failed', {
        details: {
          user_id_hash: metrics.userId.slice(0, 8) + '*'.repeat(8),
          error: error instanceof Error ? error.message : String(error)
        }
      });
    }
  }

  /**
   * Find session ID for a specific user
   */
  private async findSessionIdForUser(userId: string): Promise<string | null> {
    // For now, use a simple lookup - in production, this would be a proper database query
    // This is a temporary implementation until full database integration
    return 'temp-session-' + userId.slice(0, 8);
  }

  /**
   * Calculate summary from database
   */
  private async calculateSummaryFromDatabase(sessionId: string): Promise<MetricsSummary> {
    try {
      const metrics = await this.database.getMetrics(sessionId);
      
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
        lastUpdated: latest.createdAt.toISOString()
      };
    } catch (error) {
      logger.error('server', 'summary_calculation_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      
      return {
        totalReturn: 0,
        totalReturnPct: 0,
        totalVolume: 0,
        totalFees: 0,
        tradeCount: 0,
        lastUpdated: new Date().toISOString()
      };
    }
  }

  /**
   * Calculate summary for user (legacy method - kept for compatibility)
   */
  private calculateSummary(userId: string): MetricsSummary {
    if (!userId) {
      logger.warn('server', 'invalid_user_id', { details: { reason: 'Missing userId for summary calculation' } });
      return {
        totalReturn: 0,
        totalReturnPct: 0,
        totalVolume: 0,
        totalFees: 0,
        tradeCount: 0,
        lastUpdated: new Date().toISOString()
      };
    }

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
    if (!latest) {
      logger.warn('server', 'invalid_latest_metrics', { details: { userId: userId.slice(0, 8) + '*'.repeat(8) } });
      return {
        totalReturn: 0,
        totalReturnPct: 0,
        totalVolume: 0,
        totalFees: 0,
        tradeCount: 0,
        lastUpdated: new Date().toISOString()
      };
    }

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
    
    // Close database connection
    await this.database.close();

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

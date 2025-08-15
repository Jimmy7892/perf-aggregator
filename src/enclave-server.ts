/**
 * Secure TEE Enclave Backend Server
 * 
 * SECURITY OBJECTIVES:
 * - Accept encrypted API keys, never store them in plaintext
 * - Forward to TEE enclave for processing
 * - Return signed aggregated results only
 * - Implement comprehensive security controls
 */

import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
import { Database } from './database.js';
import { MockEnclaveService } from './enclave/mock.js';
import { EnclaveService } from './enclave/interface.js';
import type {
  SubmitKeyRequest,
  SubmitKeyResponse,
  RequestAggregatesRequest,
  RequestAggregatesResponse,
  RevokeRequest,
  RevokeResponse,
  ErrorResponse,
  HealthResponse,
  EnclaveConfig
} from './types/index.js';
import { DEFAULT_CONFIG, SECURITY_HEADERS, TTL, ERROR_MESSAGES } from './constants.js';
import { ValidationUtils } from './utils/validation.js';

// Request validation schemas
const SubmitKeySchema = z.object({
  ephemeral_pub: z.string().regex(/^[A-Za-z0-9+/]+=*$/),
  nonce: z.string().regex(/^[A-Za-z0-9+/]+=*$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9+/]+=*$/),
  tag: z.string().regex(/^[A-Za-z0-9+/]+=*$/),
  metadata: z.object({
    exchange: z.string().min(1).max(50),
    label: z.string().min(1).max(100),
    ttl: z.number().min(300).max(604800).optional() // 5 min to 7 days
  })
});

const RequestAggregatesSchema = z.object({
  session_id: z.string().uuid()
});

const RevokeSchema = z.object({
  session_id: z.string().uuid()
});

// Environment configuration
const CONFIG: EnclaveConfig = {
  port: Number(process.env.ENCLAVE_PORT) || DEFAULT_CONFIG.ENCLAVE_PORT,
  host: process.env.ENCLAVE_HOST || DEFAULT_CONFIG.ENCLAVE_HOST,
  maxTtl: Number(process.env.MAX_TTL_SECONDS) || DEFAULT_CONFIG.MAX_TTL_SECONDS,
  defaultTtl: Number(process.env.DEFAULT_TTL_SECONDS) || DEFAULT_CONFIG.DEFAULT_TTL_SECONDS,
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || DEFAULT_CONFIG.RATE_LIMIT_MAX,
  rateLimitWindow: Number(process.env.RATE_LIMIT_WINDOW) || DEFAULT_CONFIG.RATE_LIMIT_WINDOW,
};

class EnclaveServer {
  private app: any;
  private db: Database;
  private enclave: EnclaveService;

  constructor() {
    this.app = Fastify({ 
      logger: { 
        level: 'info',
        redact: ['req.body.ciphertext', 'req.body.ephemeral_pub', 'req.body.nonce', 'req.body.tag']
      }
    });
    this.db = new Database();
    this.enclave = new MockEnclaveService(); // Replace with real TEE in production
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  private async setupMiddleware() {
    // Security headers
    await this.app.register(helmet, {
      contentSecurityPolicy: {
        directives: SECURITY_HEADERS.CSP_DIRECTIVES,
      },
      hsts: SECURITY_HEADERS.HSTS
    });

    // CORS configuration
    await this.app.register(cors, {
      origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
      methods: ['GET', 'POST'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: false
    });

    // Rate limiting
    await this.app.register(rateLimit, {
      max: CONFIG.rateLimitMax,
      timeWindow: CONFIG.rateLimitWindow,
      errorResponseBuilder: (request: any, context: any) => {
        return {
          code: 429,
          error: 'Too Many Requests',
          message: `Rate limit exceeded, retry in ${Math.round(context.ttl / 1000)} seconds`
        };
      }
    });

    // Request size limit
    this.app.addContentTypeParser('application/json', { parseAs: 'string' }, (req: any, body: string, done: any) => {
      try {
        if (body.length > DEFAULT_CONFIG.REQUEST_SIZE_LIMIT) {
          done(new Error(ERROR_MESSAGES.REQUEST_TOO_LARGE), null);
          return;
        }
        const json = JSON.parse(body);
        done(null, json);
      } catch (err) {
        done(err, null);
      }
    });
  }

  private setupRoutes() {
    // Health check
    this.app.get('/health', async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const dbHealth = await this.db.healthCheck();
        const enclaveHealth = await this.enclave.health();
        
        return {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          database: dbHealth.status,
          enclave: enclaveHealth.status
        };
      } catch (error) {
        reply.code(503);
        return {
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    // Get attestation quote
    this.app.get('/attestation/quote', async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const quote = await this.enclave.getAttestationQuote();
        return quote;
      } catch (error) {
        reply.code(500);
        return {
          error: 'Failed to get attestation quote',
          details: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    // Submit encrypted API key
    this.app.post('/enclave/submit_key', async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        // Validate input
        const body = SubmitKeySchema.parse(request.body);
        
        // Create user session
        const defaultUser = await this.getOrCreateDefaultUser();
        const ttl = Math.min(body.metadata.ttl || CONFIG.defaultTtl, CONFIG.maxTtl);
        
        const session = await this.db.createSession(
          defaultUser.id,
          body.metadata.exchange,
          body.metadata.label,
          ttl
        );

        // Store encrypted credentials in database (NEVER in plaintext)
        const ciphertext = Buffer.from(body.ciphertext, 'base64');
        await this.db.storeCredentials(
          session.id,
          body.ephemeral_pub,
          body.nonce,
          ciphertext,
          body.tag,
          ttl
        );

        // Submit to enclave (enclave handles decryption internally)
        const enclaveResult = await this.enclave.submitKey(session.id, {
          ephemeral_pub: body.ephemeral_pub,
          nonce: body.nonce,
          ciphertext: body.ciphertext,
          tag: body.tag
        });

        if (!enclaveResult.success) {
          // Clean up on failure
          await this.db.deleteCredentials(session.id);
          reply.code(400);
          return {
            error: 'Failed to submit key to enclave',
            details: enclaveResult.error
          };
        }

        // Update session status
        await this.db.updateSessionStatus(session.id, 'active');

        await this.db.logOperation('INFO', `Key submitted successfully for exchange ${body.metadata.exchange}`, session.id);

        return {
          session_id: session.id
        };

      } catch (error) {
        if (error instanceof z.ZodError) {
          reply.code(400);
          return {
            error: 'Validation failed',
            details: error.errors
          };
        }

        await this.db.logOperation('ERROR', `Submit key failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        
        reply.code(500);
        return {
          error: 'Internal server error',
          details: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    // Request aggregated results
    this.app.post('/enclave/request_aggregates', async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = RequestAggregatesSchema.parse(request.body);
        
        // Verify session exists and is active
        const session = await this.db.getSession(body.session_id);
        if (!session) {
          reply.code(404);
          return { error: 'Session not found' };
        }

        if (session.status !== 'active') {
          reply.code(400);
          return { error: `Session status is ${session.status}, expected active` };
        }

        if (session.expires_at < new Date()) {
          reply.code(400);
          return { error: 'Session expired' };
        }

        // Check if aggregates already computed
        let existingAggregates = await this.db.getAggregates(body.session_id);
        if (existingAggregates) {
          return {
            aggregates_signed: existingAggregates.aggregates_signed,
            merkle_root: 'cached-result' // Would get from merkle_logs table
          };
        }

        // Request aggregates from enclave
        const result = await this.enclave.requestAggregates(body.session_id);

        // Store signed aggregates (these can be visible to operators)
        await this.db.storeAggregates(
          body.session_id,
          result.aggregates_signed,
          'enclave-mock-v1' // enclave identifier
        );

        // Store merkle proof
        await this.db.storeMerkleLog(
          body.session_id,
          result.merkle_root,
          `/api/merkle-proof/${body.session_id}` // URL for proof retrieval
        );

        // Update session status
        await this.db.updateSessionStatus(body.session_id, 'done');

        await this.db.logOperation('INFO', 'Aggregates computed successfully', body.session_id);

        return {
          aggregates_signed: result.aggregates_signed,
          merkle_root: result.merkle_root,
          logs_url: `/api/logs/${body.session_id}`
        };

      } catch (error) {
        if (error instanceof z.ZodError) {
          reply.code(400);
          return {
            error: 'Validation failed',
            details: error.errors
          };
        }

        await this.db.logOperation('ERROR', `Request aggregates failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        
        reply.code(500);
        return {
          error: 'Failed to request aggregates',
          details: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    // Revoke session and purge data
    this.app.post('/enclave/revoke', async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = RevokeSchema.parse(request.body);
        
        // Verify session exists
        const session = await this.db.getSession(body.session_id);
        if (!session) {
          reply.code(404);
          return { error: 'Session not found' };
        }

        // Revoke in enclave (purges memory and sealed storage)
        await this.enclave.revoke(body.session_id);

        // Update session status
        await this.db.updateSessionStatus(body.session_id, 'revoked');

        // Delete encrypted credentials from database
        await this.db.deleteCredentials(body.session_id);

        await this.db.logOperation('INFO', 'Session revoked and credentials purged', body.session_id);

        return {
          success: true,
          message: 'Session revoked and all data purged'
        };

      } catch (error) {
        if (error instanceof z.ZodError) {
          reply.code(400);
          return {
            error: 'Validation failed',
            details: error.errors
          };
        }

        await this.db.logOperation('ERROR', `Revoke failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        
        reply.code(500);
        return {
          error: 'Failed to revoke session',
          details: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    // Operator endpoints (metadata only, RBAC required in production)
    this.app.get('/operator/sessions', async (request: FastifyRequest, reply: FastifyReply) => {
      // TODO: Add RBAC authentication
      try {
        const sessions = await this.db.getSessionsForOperator();
        return { sessions };
      } catch (error) {
        reply.code(500);
        return { error: 'Failed to retrieve sessions' };
      }
    });

    this.app.get('/operator/users', async (request: FastifyRequest, reply: FastifyReply) => {
      // TODO: Add RBAC authentication
      try {
        const users = await this.db.getUsersForOperator();
        return { users };
      } catch (error) {
        reply.code(500);
        return { error: 'Failed to retrieve users' };
      }
    });

    this.app.get('/operator/aggregates', async (request: FastifyRequest, reply: FastifyReply) => {
      // TODO: Add RBAC authentication
      try {
        const aggregates = await this.db.getAggregatesForOperator();
        return { aggregates };
      } catch (error) {
        reply.code(500);
        return { error: 'Failed to retrieve aggregates' };
      }
    });
  }

  private async getOrCreateDefaultUser() {
    const defaultEmail = 'system@enclave.local';
    let user = await this.db.getUserByEmail(defaultEmail);
    
    if (!user) {
      user = await this.db.createUser(defaultEmail);
    }
    
    return user;
  }

  async start() {
    try {
      // Start TTL cleanup job
      this.startCleanupJob();
      
      const address = await this.app.listen({ 
        port: CONFIG.port, 
        host: CONFIG.host 
      });
      
      console.log(`🔒 Secure Enclave Backend Server running on ${address}`);
      console.log(`🛡️ Security features: Helmet, CORS, Rate Limiting, Input Validation`);
      console.log(`⚠️  Using MOCK enclave - replace with real TEE in production`);
      
    } catch (error) {
      console.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  private startCleanupJob() {
    // Run cleanup every 5 minutes
    const cleanupInterval = setInterval(async () => {
      try {
        const deletedCount = await this.db.cleanupExpiredCredentials();
        if (deletedCount > 0) {
          console.log(`🧹 Cleaned up ${deletedCount} expired credentials`);
        }
      } catch (error) {
        console.error('❌ Cleanup job failed:', error);
      }
    }, 5 * 60 * 1000);

    // Graceful shutdown
    const shutdown = async () => {
      console.log('🛑 Shutting down enclave server...');
      clearInterval(cleanupInterval);
      await this.db.close();
      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new EnclaveServer();
  server.start();
}

export { EnclaveServer };
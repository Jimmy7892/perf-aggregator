/**
 * Database connection and operations
 * 
 * SECURITY: 
 * - Uses parameterized queries to prevent SQL injection
 * - Never logs sensitive data (ciphertext, API keys)
 * - Implements proper connection pooling and error handling
 */

import { Pool, PoolClient } from 'pg';
import type {
  User,
  Session,
  Credential,
  Aggregate,
  MerkleLog
} from './types/index.js';
import { DB_CONFIG, LOG_LEVELS } from './constants.js';

export class Database {
  private pool: Pool;

  constructor(connectionString?: string) {
    this.pool = new Pool({
      connectionString: connectionString || process.env.DATABASE_URL || 'postgresql://localhost:5432/perf_aggregator',
      max: DB_CONFIG.MAX_CONNECTIONS,
      idleTimeoutMillis: DB_CONFIG.IDLE_TIMEOUT,
      connectionTimeoutMillis: DB_CONFIG.CONNECTION_TIMEOUT,
    });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // User operations
  async createUser(email: string): Promise<User> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'INSERT INTO users (email) VALUES ($1) RETURNING *',
        [email]
      );
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM users WHERE email = $1 AND status = $2',
        [email, 'active']
      );
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }

  // Session operations
  async createSession(
    userId: string, 
    exchange: string, 
    label: string, 
    ttlSeconds: number = 86400
  ): Promise<Session> {
    const client = await this.pool.connect();
    try {
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      const result = await client.query(
        'INSERT INTO sessions (user_id, exchange, label, expires_at) VALUES ($1, $2, $3, $4) RETURNING *',
        [userId, exchange, label, expiresAt]
      );
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM sessions WHERE id = $1',
        [sessionId]
      );
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }

  async updateSessionStatus(sessionId: string, status: Session['status']): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(
        'UPDATE sessions SET status = $1 WHERE id = $2',
        [status, sessionId]
      );
    } finally {
      client.release();
    }
  }

  // Credential operations (SECURITY CRITICAL)
  async storeCredentials(
    sessionId: string,
    ephemeralPub: string,
    nonce: string,
    ciphertext: Buffer,
    tag: string,
    ttlSeconds: number = 86400
  ): Promise<Credential> {
    const client = await this.pool.connect();
    try {
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      const result = await client.query(
        'INSERT INTO credentials (session_id, ephemeral_pub, nonce, ciphertext, tag, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
        [sessionId, ephemeralPub, nonce, ciphertext, tag, expiresAt]
      );
      
      // Log successful storage (without sensitive data)
      await this.logOperation('INFO', `Credentials stored for session ${sessionId}`, sessionId);
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  async getCredentials(sessionId: string): Promise<Credential | null> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM credentials WHERE session_id = $1 AND expires_at > NOW()',
        [sessionId]
      );
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }

  async deleteCredentials(sessionId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(
        'DELETE FROM credentials WHERE session_id = $1',
        [sessionId]
      );
      
      await this.logOperation('INFO', `Credentials deleted for session ${sessionId}`, sessionId);
    } finally {
      client.release();
    }
  }

  // Aggregate operations
  async storeAggregates(
    sessionId: string,
    aggregatesSigned: any,
    signedBy: string
  ): Promise<Aggregate> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'INSERT INTO aggregates (session_id, aggregates_signed, signed_by) VALUES ($1, $2, $3) RETURNING *',
        [sessionId, JSON.stringify(aggregatesSigned), signedBy]
      );
      
      await this.logOperation('INFO', `Aggregates stored for session ${sessionId}`, sessionId);
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  async getAggregates(sessionId: string): Promise<Aggregate | null> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM aggregates WHERE session_id = $1',
        [sessionId]
      );
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }

  // Merkle log operations
  async storeMerkleLog(
    sessionId: string,
    merkleRoot: string,
    proofUrl?: string
  ): Promise<MerkleLog> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'INSERT INTO merkle_logs (session_id, merkle_root, proof_url) VALUES ($1, $2, $3) RETURNING *',
        [sessionId, merkleRoot, proofUrl || null]
      );
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  // Operations logging (non-sensitive only)
  async logOperation(
    level: keyof typeof LOG_LEVELS,
    message: string,
    sessionId?: string
  ): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(
        'INSERT INTO ops_logs (level, message, session_id) VALUES ($1, $2, $3)',
        [level, message, sessionId || null]
      );
    } catch (error) {
      // If logging fails, don't crash the application
      console.error('Failed to log operation:', error);
    } finally {
      client.release();
    }
  }

  // TTL cleanup operations
  async cleanupExpiredCredentials(): Promise<number> {
    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT cleanup_expired_credentials()');
      return result.rows[0].cleanup_expired_credentials;
    } finally {
      client.release();
    }
  }

  // Operator queries (metadata only, no sensitive data)
  async getSessionsForOperator(limit: number = 100): Promise<Session[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT id, user_id, exchange, label, created_at, expires_at, status FROM sessions ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      return result.rows;
    } finally {
      client.release();
    }
  }

  async getUsersForOperator(limit: number = 100): Promise<User[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT id, email, created_at, status FROM users ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      return result.rows;
    } finally {
      client.release();
    }
  }

  async getAggregatesForOperator(limit: number = 100): Promise<Aggregate[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM aggregates ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      return result.rows;
    } finally {
      client.release();
    }
  }

  // Health check
  async healthCheck(): Promise<{ status: string; timestamp: Date }> {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT 1');
      return { status: 'healthy', timestamp: new Date() };
    } catch (error) {
      throw new Error('Database health check failed');
    } finally {
      client.release();
    }
  }
}
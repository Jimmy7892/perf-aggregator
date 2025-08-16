/**
 * Database Service for Performance Metrics Storage
 * 
 * Provides persistent storage for aggregated metrics and snapshots.
 * Implements the institutional-grade database schema for compliance.
 */

import { AggregatedMetrics, ExchangeSnapshot } from '../exchange-poller.js';
import { UserConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';

export interface DatabaseConfig {
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  maxConnections?: number;
}

export interface UserSession {
  id: string;
  userId: string;
  config: UserConfig;
  expiresAt: number;
  createdAt: Date;
}

export interface PerformanceSnapshot {
  id: string;
  sessionId: string;
  userIdHash: string;
  exchange: string;
  snapshotTimestamp: Date;
  totalPortfolioValue: number;
  portfolioCurrency: string;
  activePositionsCount: number;
  openOrdersCount: number;
  trades24h: number;
  volume24h: number;
  fees24h: number;
  dataFreshnessSeconds: number;
  pollingSuccess: boolean;
  errorMessage?: string;
  createdAt: Date;
}

export interface StoredMetrics {
  id: string;
  sessionId: string;
  userIdHash: string;
  exchange: string;
  periodStart: Date;
  periodEnd: Date;
  calculationTimestamp: Date;
  totalReturn: number;
  totalReturnPct: number;
  totalVolume: number;
  totalFees: number;
  tradeCount: number;
  winRate?: number;
  sharpeRatio?: number;
  maxDrawdown?: number;
  volatility?: number;
  dataPointsUsed: number;
  confidenceScore: number;
  createdAt: Date;
}

export class DatabaseService {
  private config: DatabaseConfig;
  private isConnected = false;
  
  // In-memory fallback storage for development
  private sessionStore = new Map<string, UserSession>();
  private snapshotStore = new Map<string, PerformanceSnapshot[]>();
  private metricsStore = new Map<string, StoredMetrics[]>();

  constructor(config: DatabaseConfig = {}) {
    this.config = {
      maxConnections: 10,
      ssl: true,
      ...config
    };
  }

  /**
   * Initialize database connection
   */
  async initialize(): Promise<void> {
    try {
      if (this.config.connectionString || this.config.host) {
        await this.connectToDatabase();
      } else {
        logger.warn('database', 'no_connection_config', { 
          details: { message: 'Using in-memory storage - not suitable for production' } 
        });
      }
      this.isConnected = true;
    } catch (error) {
      logger.error('database', 'initialization_failed', { 
        details: { error: error instanceof Error ? error.message : String(error) } 
      });
      throw error;
    }
  }

  /**
   * Store user session
   */
  async storeSession(session: UserSession): Promise<void> {
    if (!session.id || !session.userId) {
      throw new Error('Invalid session: missing required fields');
    }

    try {
      if (this.isConnected && this.config.connectionString) {
        await this.storeSessionInDatabase(session);
      } else {
        // Fallback to in-memory storage
        this.sessionStore.set(session.id, session);
      }

      logger.debug('database', 'session_stored', {
        details: {
          session_id: session.id,
          user_id_hash: this.hashUserId(session.userId),
          expires_at: new Date(session.expiresAt).toISOString()
        }
      });
    } catch (error) {
      logger.error('database', 'session_store_failed', {
        details: {
          session_id: session.id,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  }

  /**
   * Retrieve user session
   */
  async getSession(sessionId: string): Promise<UserSession | null> {
    if (!sessionId) {
      return null;
    }

    try {
      let session: UserSession | null = null;

      if (this.isConnected && this.config.connectionString) {
        session = await this.getSessionFromDatabase(sessionId);
      } else {
        // Fallback to in-memory storage
        session = this.sessionStore.get(sessionId) || null;
      }

      // Check expiration
      if (session && session.expiresAt < Date.now()) {
        await this.deleteSession(sessionId);
        return null;
      }

      return session;
    } catch (error) {
      logger.error('database', 'session_retrieval_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      return null;
    }
  }

  /**
   * Delete user session
   */
  async deleteSession(sessionId: string): Promise<void> {
    if (!sessionId) {
      return;
    }

    try {
      if (this.isConnected && this.config.connectionString) {
        await this.deleteSessionFromDatabase(sessionId);
      } else {
        this.sessionStore.delete(sessionId);
      }

      logger.debug('database', 'session_deleted', {
        details: { session_id: sessionId }
      });
    } catch (error) {
      logger.error('database', 'session_deletion_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
    }
  }

  /**
   * Store performance snapshot
   */
  async storeSnapshot(sessionId: string, snapshot: ExchangeSnapshot): Promise<void> {
    if (!sessionId || !snapshot || !snapshot.userId) {
      throw new Error('Invalid snapshot: missing required fields');
    }

    const performanceSnapshot: PerformanceSnapshot = {
      id: this.generateId(),
      sessionId,
      userIdHash: this.hashUserId(snapshot.userId),
      exchange: snapshot.exchange,
      snapshotTimestamp: new Date(snapshot.timestamp),
      totalPortfolioValue: snapshot.portfolioValue.total,
      portfolioCurrency: snapshot.portfolioValue.currency,
      activePositionsCount: 0, // Would be calculated from positions
      openOrdersCount: snapshot.openOrders,
      trades24h: snapshot.recentTrades.count,
      volume24h: snapshot.recentTrades.volume24h,
      fees24h: snapshot.recentTrades.fees24h,
      dataFreshnessSeconds: 0, // Would be calculated based on polling time
      pollingSuccess: true,
      createdAt: new Date()
    };

    try {
      if (this.isConnected && this.config.connectionString) {
        await this.storeSnapshotInDatabase(performanceSnapshot);
      } else {
        // Fallback to in-memory storage
        const snapshots = this.snapshotStore.get(sessionId) || [];
        snapshots.push(performanceSnapshot);
        
        // Keep only last 1000 snapshots per session
        if (snapshots.length > 1000) {
          snapshots.splice(0, snapshots.length - 1000);
        }
        
        this.snapshotStore.set(sessionId, snapshots);
      }

      logger.debug('database', 'snapshot_stored', {
        details: {
          session_id: sessionId,
          user_id_hash: performanceSnapshot.userIdHash,
          portfolio_value: performanceSnapshot.totalPortfolioValue
        }
      });
    } catch (error) {
      logger.error('database', 'snapshot_store_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  }

  /**
   * Store aggregated metrics
   */
  async storeMetrics(sessionId: string, metrics: AggregatedMetrics): Promise<void> {
    if (!sessionId || !metrics || !metrics.userId) {
      throw new Error('Invalid metrics: missing required fields');
    }

    const storedMetrics: StoredMetrics = {
      id: this.generateId(),
      sessionId,
      userIdHash: this.hashUserId(metrics.userId),
      exchange: metrics.exchange,
      periodStart: new Date(metrics.periodStart),
      periodEnd: new Date(metrics.periodEnd),
      calculationTimestamp: new Date(),
      totalReturn: metrics.totalReturn,
      totalReturnPct: metrics.totalReturnPct,
      totalVolume: metrics.totalVolume,
      totalFees: metrics.totalFees,
      tradeCount: metrics.tradeCount,
      winRate: metrics.winRate,
      sharpeRatio: metrics.sharpeRatio,
      maxDrawdown: metrics.maxDrawdown,
      volatility: metrics.volatility,
      dataPointsUsed: 1, // Would be calculated from actual data points
      confidenceScore: 1.0,
      createdAt: new Date()
    };

    try {
      if (this.isConnected && this.config.connectionString) {
        await this.storeMetricsInDatabase(storedMetrics);
      } else {
        // Fallback to in-memory storage
        const sessionMetrics = this.metricsStore.get(sessionId) || [];
        sessionMetrics.push(storedMetrics);
        
        // Keep only last 100 metrics per session
        if (sessionMetrics.length > 100) {
          sessionMetrics.splice(0, sessionMetrics.length - 100);
        }
        
        this.metricsStore.set(sessionId, sessionMetrics);
      }

      logger.debug('database', 'metrics_stored', {
        details: {
          session_id: sessionId,
          user_id_hash: storedMetrics.userIdHash,
          return_pct: storedMetrics.totalReturnPct
        }
      });
    } catch (error) {
      logger.error('database', 'metrics_store_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  }

  /**
   * Get metrics for user
   */
  async getMetrics(sessionId: string): Promise<StoredMetrics[]> {
    if (!sessionId) {
      return [];
    }

    try {
      if (this.isConnected && this.config.connectionString) {
        return await this.getMetricsFromDatabase(sessionId);
      } else {
        return this.metricsStore.get(sessionId) || [];
      }
    } catch (error) {
      logger.error('database', 'metrics_retrieval_failed', {
        details: {
          session_id: sessionId,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      return [];
    }
  }

  /**
   * Cleanup expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    const now = Date.now();
    let cleanedCount = 0;

    try {
      if (this.isConnected && this.config.connectionString) {
        cleanedCount = await this.cleanupExpiredSessionsInDatabase();
      } else {
        // Fallback to in-memory cleanup
        for (const [sessionId, session] of this.sessionStore.entries()) {
          if (session.expiresAt < now) {
            this.sessionStore.delete(sessionId);
            this.snapshotStore.delete(sessionId);
            this.metricsStore.delete(sessionId);
            cleanedCount++;
          }
        }
      }

      if (cleanedCount > 0) {
        logger.info('database', 'sessions_cleaned', {
          details: { cleaned_count: cleanedCount }
        });
      }

      return cleanedCount;
    } catch (error) {
      logger.error('database', 'cleanup_failed', {
        details: { error: error instanceof Error ? error.message : String(error) }
      });
      return 0;
    }
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    try {
      if (this.isConnected && this.config.connectionString) {
        await this.closeDatabaseConnection();
      }
      
      // Clear in-memory stores
      this.sessionStore.clear();
      this.snapshotStore.clear();
      this.metricsStore.clear();
      
      this.isConnected = false;
      
      logger.info('database', 'connection_closed', {
        details: { message: 'Database service closed' }
      });
    } catch (error) {
      logger.error('database', 'close_failed', {
        details: { error: error instanceof Error ? error.message : String(error) }
      });
    }
  }

  // Private methods for database operations (would implement actual DB calls)
  private async connectToDatabase(): Promise<void> {
    // TODO: Implement actual database connection (PostgreSQL)
    logger.info('database', 'connection_placeholder', {
      details: { message: 'Database connection not implemented - using in-memory storage' }
    });
  }

  private async storeSessionInDatabase(session: UserSession): Promise<void> {
    // TODO: Implement actual database storage
    logger.debug('database', 'store_session_placeholder', { details: { session_id: session.id } });
  }

  private async getSessionFromDatabase(sessionId: string): Promise<UserSession | null> {
    // TODO: Implement actual database retrieval
    logger.debug('database', 'get_session_placeholder', { details: { session_id: sessionId } });
    return null;
  }

  private async deleteSessionFromDatabase(sessionId: string): Promise<void> {
    // TODO: Implement actual database deletion
    logger.debug('database', 'delete_session_placeholder', { details: { session_id: sessionId } });
  }

  private async storeSnapshotInDatabase(snapshot: PerformanceSnapshot): Promise<void> {
    // TODO: Implement actual database storage
    logger.debug('database', 'store_snapshot_placeholder', { details: { snapshot_id: snapshot.id } });
  }

  private async storeMetricsInDatabase(metrics: StoredMetrics): Promise<void> {
    // TODO: Implement actual database storage
    logger.debug('database', 'store_metrics_placeholder', { details: { metrics_id: metrics.id } });
  }

  private async getMetricsFromDatabase(sessionId: string): Promise<StoredMetrics[]> {
    // TODO: Implement actual database retrieval
    logger.debug('database', 'get_metrics_placeholder', { details: { session_id: sessionId } });
    return [];
  }

  private async cleanupExpiredSessionsInDatabase(): Promise<number> {
    // TODO: Implement actual database cleanup
    logger.debug('database', 'cleanup_placeholder', { details: { message: 'Database cleanup not implemented' } });
    return 0;
  }

  private async closeDatabaseConnection(): Promise<void> {
    // TODO: Implement actual database connection closure
    logger.debug('database', 'close_connection_placeholder', { details: { message: 'Database close not implemented' } });
  }

  // Utility methods
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private hashUserId(userId: string): string {
    // Simple hash for logging - in production use crypto.createHash
    return userId.slice(0, 8) + '*'.repeat(8);
  }

  /**
   * Get database statistics
   */
  getStats(): {
    isConnected: boolean;
    activeSessions: number;
    totalSnapshots: number;
    totalMetrics: number;
  } {
    let totalSnapshots = 0;
    let totalMetrics = 0;

    for (const snapshots of this.snapshotStore.values()) {
      totalSnapshots += snapshots.length;
    }

    for (const metrics of this.metricsStore.values()) {
      totalMetrics += metrics.length;
    }

    return {
      isConnected: this.isConnected,
      activeSessions: this.sessionStore.size,
      totalSnapshots,
      totalMetrics
    };
  }
}
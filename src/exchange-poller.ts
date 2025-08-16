/**
 * Institutional Exchange Polling Service
 * 
 * Professional-grade polling implementation for institutional trading environments.
 * Replaces WebSocket connections with reliable, auditable REST API polling.
 * 
 * SECURITY REQUIREMENTS:
 * - All API calls are authenticated and rate-limited
 * - No raw trade data is stored, only aggregated metrics
 * - All operations are logged for compliance and audit
 * - Error handling is comprehensive and institutional-grade
 */

import { EventEmitter } from 'events';
import { logger } from './utils/logger.js';
import { UserConfig } from './types/index.js';
import ccxt from 'ccxt';

export interface PollingConfig {
  intervalSeconds: number;
  maxRetries: number;
  retryDelayMs: number;
  timeoutMs: number;
  enableRateLimit: boolean;
}

export interface ExchangeSnapshot {
  userId: string;
  exchange: string;
  timestamp: number;
  balances: Record<string, number>;
  openOrders: number;
  recentTrades: {
    count: number;
    volume24h: number;
    fees24h: number;
  };
  portfolioValue: {
    total: number;
    currency: string;
  };
}

export interface AggregatedMetrics {
  userId: string;
  exchange: string;
  periodStart: string;
  periodEnd: string;
  totalReturn: number;
  totalReturnPct: number;
  totalVolume: number;
  totalFees: number;
  tradeCount: number;
  winRate: number;
  sharpeRatio: number;
  maxDrawdown: number;
  volatility: number;
  lastUpdated: string;
}

export class ExchangePoller extends EventEmitter {
  private pollingTimers = new Map<string, NodeJS.Timeout>();
  private userConfigs = new Map<string, UserConfig>();
  private exchangeClients = new Map<string, ccxt.Exchange>();
  private isRunning = false;

  private readonly defaultConfig: PollingConfig = {
    intervalSeconds: 300, // 5 minutes - institutional standard
    maxRetries: 3,
    retryDelayMs: 5000,
    timeoutMs: 30000,
    enableRateLimit: true
  };

  constructor(private config: Partial<PollingConfig> = {}) {
    super();
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Add a user configuration for polling
   * Initializes exchange client and starts polling
   */
  async addUser(userConfig: UserConfig): Promise<void> {
    const userId = userConfig.userId;
    
    try {
      logger.info('exchange_poller', 'user_added', {
        details: {
          user_id_hash: this.hashUserId(userId),
          exchange: userConfig.exchange,
          account_type: userConfig.accountType
        }
      });

      // Store user configuration
      this.userConfigs.set(userId, userConfig);

      // Initialize exchange client
      await this.initializeExchangeClient(userConfig);

      // Start polling for this user
      if (this.isRunning) {
        await this.startPollingForUser(userId);
      }

    } catch (error) {
      logger.error('exchange_poller', 'user_add_failed', {
        details: {
          user_id_hash: this.hashUserId(userId),
          exchange: userConfig.exchange,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  }

  /**
   * Remove user and stop polling
   */
  async removeUser(userId: string): Promise<void> {
    try {
      // Stop polling
      const timer = this.pollingTimers.get(userId);
      if (timer) {
        clearInterval(timer);
        this.pollingTimers.delete(userId);
      }

      // Close exchange client
      const clientKey = this.getExchangeClientKey(userId);
      const client = this.exchangeClients.get(clientKey);
      if (client) {
        // Cleanup exchange client resources
        this.exchangeClients.delete(clientKey);
      }

      // Remove user config
      this.userConfigs.delete(userId);

      logger.info('exchange_poller', 'user_removed', {
        details: {
          user_id_hash: this.hashUserId(userId)
        }
      });

    } catch (error) {
      logger.error('exchange_poller', 'user_removal_failed', {
        details: {
          user_id_hash: this.hashUserId(userId),
          error: error instanceof Error ? error.message : String(error)
        }
      });
    }
  }

  /**
   * Start polling service
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;

    logger.info('exchange_poller', 'service_started', {
      details: {
        interval_seconds: this.config.intervalSeconds,
        max_retries: this.config.maxRetries,
        active_users: this.userConfigs.size
      }
    });

    // Start polling for all configured users
    for (const userId of this.userConfigs.keys()) {
      await this.startPollingForUser(userId);
    }
  }

  /**
   * Stop polling service
   */
  async stop(): Promise<void> {
    this.isRunning = false;

    // Stop all polling timers
    for (const timer of this.pollingTimers.values()) {
      clearInterval(timer);
    }
    this.pollingTimers.clear();

    // Close all exchange clients
    this.exchangeClients.clear();

    logger.info('exchange_poller', 'service_stopped', {
      details: {
        message: 'Exchange polling service stopped'
      }
    });
  }

  /**
   * Initialize exchange client with user credentials
   */
  private async initializeExchangeClient(userConfig: UserConfig): Promise<void> {
    const clientKey = this.getExchangeClientKey(userConfig.userId);

    try {
      // Get exchange class
      const ExchangeClass = ccxt[userConfig.exchange as keyof typeof ccxt] as any;
      if (!ExchangeClass) {
        throw new Error(`Unsupported exchange: ${userConfig.exchange}`);
      }

      // Initialize client with institutional-grade configuration
      const client = new ExchangeClass({
        apiKey: userConfig.apiKey,
        secret: userConfig.secret,
        sandbox: userConfig.sandbox || false,
        rateLimit: this.config.enableRateLimit,
        timeout: this.config.timeoutMs,
        enableRateLimit: this.config.enableRateLimit,
        // Institutional trading specific options
        options: {
          defaultType: userConfig.accountType || 'spot',
          recvWindow: 60000, // Extended receive window for institutional APIs
          adjustForTimeDifference: true
        }
      });

      // Test connection
      await client.loadMarkets();
      
      this.exchangeClients.set(clientKey, client);

      logger.info('exchange_poller', 'exchange_client_initialized', {
        details: {
          user_id_hash: this.hashUserId(userConfig.userId),
          exchange: userConfig.exchange,
          sandbox: userConfig.sandbox,
          account_type: userConfig.accountType
        }
      });

    } catch (error) {
      logger.error('exchange_poller', 'exchange_client_init_failed', {
        details: {
          user_id_hash: this.hashUserId(userConfig.userId),
          exchange: userConfig.exchange,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  }

  /**
   * Start polling for specific user
   */
  private async startPollingForUser(userId: string): Promise<void> {
    const userConfig = this.userConfigs.get(userId);
    if (!userConfig) {
      throw new Error(`User configuration not found: ${userId}`);
    }

    // Clear any existing timer
    const existingTimer = this.pollingTimers.get(userId);
    if (existingTimer) {
      clearInterval(existingTimer);
    }

    // Start new polling timer
    const timer = setInterval(async () => {
      await this.pollUserData(userId);
    }, this.config.intervalSeconds! * 1000);

    this.pollingTimers.set(userId, timer);

    // Perform initial poll
    setTimeout(() => {
      this.pollUserData(userId).catch(error => {
        logger.error('exchange_poller', 'initial_poll_failed', {
          details: {
            user_id_hash: this.hashUserId(userId),
            error: error instanceof Error ? error.message : String(error)
          }
        });
      });
    }, 1000);

    logger.info('exchange_poller', 'polling_started', {
      details: {
        user_id_hash: this.hashUserId(userId),
        interval_seconds: this.config.intervalSeconds
      }
    });
  }

  /**
   * Poll data for specific user with retry logic
   */
  private async pollUserData(userId: string): Promise<void> {
    const userConfig = this.userConfigs.get(userId);
    if (!userConfig) {
      return;
    }

    const clientKey = this.getExchangeClientKey(userId);
    const client = this.exchangeClients.get(clientKey);
    if (!client) {
      logger.error('exchange_poller', 'client_not_found', {
        details: {
          user_id_hash: this.hashUserId(userId)
        }
      });
      return;
    }

    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= this.config.maxRetries!; attempt++) {
      try {
        const snapshot = await this.fetchExchangeSnapshot(client, userConfig);
        
        // Emit snapshot for processing
        this.emit('snapshot', snapshot);

        // Calculate and emit aggregated metrics
        const metrics = await this.calculateMetrics(snapshot);
        this.emit('metrics', metrics);

        logger.debug('exchange_poller', 'poll_successful', {
          details: {
            user_id_hash: this.hashUserId(userId),
            attempt,
            portfolio_value: snapshot.portfolioValue.total
          }
        });

        return; // Success, exit retry loop

      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        logger.warn('exchange_poller', 'poll_attempt_failed', {
          details: {
            user_id_hash: this.hashUserId(userId),
            attempt,
            max_retries: this.config.maxRetries,
            error: lastError.message
          }
        });

        if (attempt < this.config.maxRetries!) {
          await this.sleep(this.config.retryDelayMs!);
        }
      }
    }

    // All retries failed
    logger.error('exchange_poller', 'poll_failed_all_retries', {
      details: {
        user_id_hash: this.hashUserId(userId),
        max_retries: this.config.maxRetries,
        error: lastError?.message || 'Unknown error'
      }
    });

    // Emit error for handling
    this.emit('error', {
      userId,
      error: lastError,
      type: 'polling_failed'
    });
  }

  /**
   * Fetch exchange snapshot (account state at point in time)
   */
  private async fetchExchangeSnapshot(
    client: ccxt.Exchange, 
    userConfig: UserConfig
  ): Promise<ExchangeSnapshot> {
    
    // Fetch account data in parallel for efficiency
    const [balance, openOrders, recentTrades] = await Promise.all([
      client.fetchBalance(),
      client.fetchOpenOrders(),
      this.fetchRecentTradesSummary(client)
    ]);

    // Calculate portfolio value
    const portfolioValue = this.calculatePortfolioValue(balance, client);

    const snapshot: ExchangeSnapshot = {
      userId: userConfig.userId,
      exchange: userConfig.exchange,
      timestamp: Date.now(),
      balances: this.sanitizeBalances(balance),
      openOrders: openOrders.length,
      recentTrades,
      portfolioValue
    };

    return snapshot;
  }

  /**
   * Fetch recent trades summary (aggregated, not raw trades)
   */
  private async fetchRecentTradesSummary(client: ccxt.Exchange): Promise<{
    count: number;
    volume24h: number;
    fees24h: number;
  }> {
    try {
      // Fetch trades from last 24 hours
      const since = Date.now() - (24 * 60 * 60 * 1000);
      const trades = await client.fetchMyTrades(undefined, since);

      // Aggregate data (no raw trade storage)
      const volume24h = trades.reduce((sum, trade) => sum + (trade.amount * trade.price), 0);
      const fees24h = trades.reduce((sum, trade) => sum + (trade.fee?.cost || 0), 0);

      return {
        count: trades.length,
        volume24h,
        fees24h
      };

    } catch (error) {
      // Non-critical error, return zeros
      logger.warn('exchange_poller', 'trades_summary_failed', {
        details: {
          error: error instanceof Error ? error.message : String(error)
        }
      });

      return {
        count: 0,
        volume24h: 0,
        fees24h: 0
      };
    }
  }

  /**
   * Calculate portfolio value in USD
   */
  private calculatePortfolioValue(balance: any, client: ccxt.Exchange): {
    total: number;
    currency: string;
  } {
    // Simplified calculation - in production, use real-time pricing
    const totalValue = Object.entries(balance.total)
      .filter(([symbol, amount]) => (amount as number) > 0)
      .reduce((sum, [symbol, amount]) => {
        // Use last price or estimate - institutional systems would use real-time pricing
        return sum + (amount as number);
      }, 0);

    return {
      total: totalValue,
      currency: 'USD'
    };
  }

  /**
   * Sanitize balances for logging (remove dust and zero balances)
   */
  private sanitizeBalances(balance: any): Record<string, number> {
    const sanitized: Record<string, number> = {};
    const minBalance = 0.001; // Minimum balance to report

    for (const [symbol, amount] of Object.entries(balance.total)) {
      if ((amount as number) >= minBalance) {
        sanitized[symbol] = amount as number;
      }
    }

    return sanitized;
  }

  /**
   * Calculate aggregated metrics from snapshot
   */
  private async calculateMetrics(snapshot: ExchangeSnapshot): Promise<AggregatedMetrics> {
    // This would integrate with a metrics calculation engine
    // For now, return basic structure
    
    const now = new Date();
    const periodStart = new Date(now.getTime() - (24 * 60 * 60 * 1000)); // 24h ago

    return {
      userId: snapshot.userId,
      exchange: snapshot.exchange,
      periodStart: periodStart.toISOString(),
      periodEnd: now.toISOString(),
      totalReturn: 0, // Calculate from historical data
      totalReturnPct: 0,
      totalVolume: snapshot.recentTrades.volume24h,
      totalFees: snapshot.recentTrades.fees24h,
      tradeCount: snapshot.recentTrades.count,
      winRate: 0, // Calculate from trade history
      sharpeRatio: 0, // Calculate from returns
      maxDrawdown: 0, // Calculate from portfolio history
      volatility: 0, // Calculate from price movements
      lastUpdated: now.toISOString()
    };
  }

  /**
   * Utility methods
   */
  private getExchangeClientKey(userId: string): string {
    return `${userId}`;
  }

  private hashUserId(userId: string): string {
    // Simple hash for logging - use crypto.createHash in production
    return userId.slice(0, 8) + '*'.repeat(8);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current polling statistics
   */
  getStats(): {
    activeUsers: number;
    pollingInterval: number;
    isRunning: boolean;
  } {
    return {
      activeUsers: this.userConfigs.size,
      pollingInterval: this.config.intervalSeconds!,
      isRunning: this.isRunning
    };
  }
}
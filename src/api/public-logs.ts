/**
 * Public Logs API Server
 *
 * Provides read-only access to sanitized application logs
 * Runs on separate port for public consumption
 */

import Fastify from 'fastify';
import { logger, PublicLogFilter } from '../utils/logger.js';
import { getConfig } from '../config/index.js';

export class PublicLogsServer {
  private fastify: any;
  private config = getConfig();

  constructor() {
    this.fastify = Fastify({
      logger: false, // Disable Fastify's own logging to avoid recursion
      bodyLimit: 1048576 // 1MB limit
    });

    this.setupRoutes();
    this.setupMiddleware();
  }

  private setupMiddleware(): void {
    // CORS for public access
    this.fastify.register(import('@fastify/cors'), {
      origin: true, // Allow all origins for public logs
      credentials: false
    });

    // Rate limiting for public endpoint
    this.fastify.register(import('@fastify/rate-limit'), {
      max: 100,
      timeWindow: '1 minute'
    });

    // Security headers
    this.fastify.register(import('@fastify/helmet'), {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ['\'self\''],
          scriptSrc: ['\'self\''],
          styleSrc: ['\'self\'', '\'unsafe-inline\''],
          imgSrc: ['\'self\'', 'data:']
        }
      }
    });
  }

  private setupRoutes(): void {
    // Health check for public logs service
    this.fastify.get('/health', async (request: any, reply: any) => {
      return {
        status: 'healthy',
        service: 'public-logs',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      };
    });

    // Get public logs with filtering
    this.fastify.get('/logs', async (request: any, reply: any) => {
      try {
        const query = request.query as any;

        const filter: PublicLogFilter = {
          level: query.level,
          service: query.service,
          event: query.event,
          since: query.since,
          limit: query.limit ? parseInt(query.limit, 10) : 100
        };

        // Validate limit
        if (filter.limit && (filter.limit > 1000 || filter.limit < 1)) {
          return reply.status(400).send({
            error: 'Invalid limit. Must be between 1 and 1000'
          });
        }

        const logs = logger.getPublicLogs(filter);

        return {
          logs,
          count: logs.length,
          filter,
          timestamp: new Date().toISOString()
        };

      } catch (error) {
        logger.error('public-logs', 'query_error', {
          error_code: 'LOG_QUERY_FAILED',
          details: { message: error instanceof Error ? error.message : 'Unknown error' }
        });

        return reply.status(500).send({
          error: 'Failed to retrieve logs'
        });
      }
    });

    // Get logs by service
    this.fastify.get('/logs/service/:service', async (request: any, reply: any) => {
      try {
        const { service } = request.params;
        const query = request.query as any;

        const filter: PublicLogFilter = {
          service,
          level: query.level,
          event: query.event,
          since: query.since,
          limit: query.limit ? parseInt(query.limit, 10) : 100
        };

        const logs = logger.getPublicLogs(filter);

        return {
          service,
          logs,
          count: logs.length,
          timestamp: new Date().toISOString()
        };

      } catch (error) {
        return reply.status(500).send({
          error: 'Failed to retrieve service logs'
        });
      }
    });

    // Get log statistics
    this.fastify.get('/logs/stats', async (request: any, reply: any) => {
      try {
        const allLogs = logger.getPublicLogs({ limit: 10000 }); // Get recent logs for stats

        const stats = {
          total_logs: allLogs.length,
          services: this.getUniqueValues(allLogs, 'service'),
          events: this.getUniqueValues(allLogs, 'event'),
          levels: this.getUniqueValues(allLogs, 'level'),
          recent_activity: allLogs.slice(0, 10).map(log => ({
            timestamp: log.timestamp,
            service: log.service,
            event: log.event,
            level: log.level
          })),
          timestamp: new Date().toISOString()
        };

        return stats;

      } catch (error) {
        return reply.status(500).send({
          error: 'Failed to retrieve log statistics'
        });
      }
    });

    // Real-time log stream (Server-Sent Events)
    this.fastify.get('/logs/stream', async (request: any, reply: any) => {
      reply.type('text/event-stream');
      reply.header('Cache-Control', 'no-cache');
      reply.header('Connection', 'keep-alive');
      reply.header('Access-Control-Allow-Origin', '*');

      // Send initial connection event
      reply.send(`data: ${JSON.stringify({
        type: 'connected',
        timestamp: new Date().toISOString(),
        message: 'Connected to log stream'
      })}\n\n`);

      // Get recent logs and send them
      const recentLogs = logger.getPublicLogs({ limit: 50 });
      for (const log of recentLogs.reverse()) {
        reply.send(`data: ${JSON.stringify({
          type: 'log',
          ...log
        })}\n\n`);
      }

      // Keep connection alive with periodic ping
      const pingInterval = setInterval(() => {
        reply.send(`data: ${JSON.stringify({
          type: 'ping',
          timestamp: new Date().toISOString()
        })}\n\n`);
      }, 30000); // 30 seconds

      // Cleanup on client disconnect
      request.socket.on('close', () => {
        clearInterval(pingInterval);
      });

      return reply;
    });

    // API documentation endpoint
    this.fastify.get('/docs', async (request: any, reply: any) => {
      const docs = {
        title: 'Public Logs API',
        version: '1.0.0',
        description: 'Read-only access to sanitized application logs',
        endpoints: {
          'GET /health': 'Health check',
          'GET /logs': 'Get filtered logs (query: level, service, event, since, limit)',
          'GET /logs/service/:service': 'Get logs for specific service',
          'GET /logs/stats': 'Get log statistics and recent activity',
          'GET /logs/stream': 'Real-time log stream (Server-Sent Events)',
          'GET /docs': 'This documentation'
        },
        filters: {
          level: ['error', 'warn', 'info', 'debug'],
          since: 'ISO timestamp (e.g., 2024-01-01T00:00:00Z)',
          limit: 'Number (1-1000, default: 100)'
        },
        security: {
          note: 'All logs are automatically sanitized. No sensitive data is exposed.',
          rate_limit: '100 requests per minute'
        }
      };

      reply.type('application/json');
      return docs;
    });
  }

  /**
   * Helper to get unique values from log array
   */
  private getUniqueValues(logs: any[], field: string): string[] {
    return Array.from(new Set(logs.map(log => log[field]).filter(Boolean)));
  }

  /**
   * Start the public logs server
   */
  async start(): Promise<void> {
    try {
      const port = this.config.logging.publicPort;
      await this.fastify.listen({ port, host: '0.0.0.0' });

      logger.info('public-logs', 'server_started', {
        details: { port, message: 'Public logs server running' }
      });

      console.log(`📊 Public Logs API available at http://0.0.0.0:${port}`);
      console.log(`📖 Documentation: http://0.0.0.0:${port}/docs`);
      console.log(`🔄 Live stream: http://0.0.0.0:${port}/logs/stream`);

    } catch (error) {
      logger.error('public-logs', 'server_start_failed', {
        error_code: 'STARTUP_FAILED',
        details: { message: error instanceof Error ? error.message : 'Unknown error' }
      });
      throw error;
    }
  }

  /**
   * Stop the public logs server
   */
  async stop(): Promise<void> {
    await this.fastify.close();
    logger.info('public-logs', 'server_stopped', {
      details: { message: 'Public logs server stopped' }
    });
  }
}

/**
 * Secure Public Logging System
 *
 * SECURITY CRITICAL: This logger is designed for public consumption.
 * - NEVER log API keys, secrets, or PII
 * - Sanitize all user inputs
 * - Only log operational and audit information
 */

import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { getEnvironment } from '../config/environment';

export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  service: string;
  event: string;
  session_id?: string;
  user_id_hash?: string; // SHA256 hash of user ID for correlation
  exchange?: string;
  details?: Record<string, any>;
  duration_ms?: number;
  error_code?: string;
}

export interface PublicLogFilter {
  level?: LogLevel;
  service?: string;
  event?: string;
  since?: string; // ISO timestamp
  limit?: number;
}

class SecureLogger {
  private readonly logDir: string;
  private readonly logFile: string;
  private readonly publicLogFile: string;
  private readonly env = getEnvironment();

  constructor() {
    this.logDir = join(process.cwd(), 'logs');
    this.logFile = join(this.logDir, 'application.log');
    this.publicLogFile = join(this.logDir, 'public.log');

    // Ensure log directory exists
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true });
    }
  }

  /**
   * Log an event with automatic sanitization
   */
  log(level: LogLevel, service: string, event: string, data?: Partial<LogEntry>): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      service,
      event,
      ...this.sanitizeLogData(data || {})
    };

    // Write to internal log
    this.writeToFile(this.logFile, entry);

    // Write to public log if enabled and appropriate level
    if (this.env.PUBLIC_LOGS_ENABLED && this.shouldLogPublically(level, event)) {
      const publicEntry = this.createPublicLogEntry(entry);
      this.writeToFile(this.publicLogFile, publicEntry);
    }

    // Console output in development
    if (this.env.NODE_ENV === 'development') {
      console.log(`[${entry.timestamp}] ${entry.level.toUpperCase()} ${entry.service}:${entry.event}`,
        entry.details ? JSON.stringify(entry.details, null, 2) : '');
    }
  }

  /**
   * Convenience methods for different log levels
   */
  error(service: string, event: string, data?: Partial<LogEntry>): void {
    this.log('error', service, event, data);
  }

  warn(service: string, event: string, data?: Partial<LogEntry>): void {
    this.log('warn', service, event, data);
  }

  info(service: string, event: string, data?: Partial<LogEntry>): void {
    this.log('info', service, event, data);
  }

  debug(service: string, event: string, data?: Partial<LogEntry>): void {
    this.log('debug', service, event, data);
  }

  /**
   * Log user session events (automatically sanitized)
   */
  logSessionEvent(event: string, sessionId: string, userId: string, data?: Record<string, any>): void {
    this.info('session', event, {
      session_id: this.sanitizeSessionId(sessionId),
      user_id_hash: this.hashUserId(userId),
      details: this.sanitizeLogData(data || {})
    });
  }

  /**
   * Log exchange operations
   */
  logExchangeEvent(event: string, exchange: string, userId: string, data?: Record<string, any>): void {
    this.info('exchange', event, {
      exchange,
      user_id_hash: this.hashUserId(userId),
      details: this.sanitizeLogData(data || {})
    });
  }

  /**
   * Log security events
   */
  logSecurityEvent(event: string, data?: Record<string, any>): void {
    this.warn('security', event, {
      details: this.sanitizeLogData(data || {})
    });
  }

  /**
   * Get public logs with filtering
   */
  getPublicLogs(filter: PublicLogFilter = {}): LogEntry[] {
    if (!this.env.PUBLIC_LOGS_ENABLED) {
      return [];
    }

    try {
      const content = require('fs').readFileSync(this.publicLogFile, 'utf8');
      const lines = content.trim().split('\n').filter((line: string) => line.trim());

      let logs = lines.map((line: string) => {
        try {
          return JSON.parse(line) as LogEntry;
        } catch {
          return null;
        }
      }).filter(Boolean) as LogEntry[];

      // Apply filters
      if (filter.level) {
        logs = logs.filter(log => log.level === filter.level);
      }
      if (filter.service) {
        logs = logs.filter(log => log.service === filter.service);
      }
      if (filter.event) {
        logs = logs.filter(log => log.event === filter.event);
      }
      if (filter.since) {
        logs = logs.filter(log => log.timestamp >= filter.since!);
      }

      // Sort by timestamp (newest first) and apply limit
      logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      if (filter.limit) {
        logs = logs.slice(0, filter.limit);
      }

      return logs;
    } catch {
      return [];
    }
  }

  /**
   * SECURITY: Sanitize log data to prevent sensitive information exposure
   */
  private sanitizeLogData(data: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(data)) {
      // Skip sensitive fields entirely
      if (this.isSensitiveField(key)) {
        continue;
      }

      // Sanitize string values
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize objects
        sanitized[key] = this.sanitizeLogData(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Check if a field contains sensitive information
   */
  private isSensitiveField(fieldName: string): boolean {
    const sensitiveFields = [
      'apikey', 'api_key', 'secret', 'password', 'token', 'credential',
      'private_key', 'public_key', 'auth', 'authorization', 'bearer',
      'session_secret', 'encryption_key', 'nonce', 'ciphertext'
    ];

    return sensitiveFields.some(field =>
      fieldName.toLowerCase().includes(field)
    );
  }

  /**
   * Sanitize string values to prevent sensitive data exposure
   */
  private sanitizeString(value: string): string {
    // Truncate very long strings that might contain sensitive data
    if (value.length > 200) {
      return `${value.substring(0, 200)}...[truncated]`;
    }

    // Mask potential API keys or secrets (base64 patterns)
    if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(value)) {
      return value.substring(0, 8) + '*'.repeat(Math.min(16, value.length - 8));
    }

    return value;
  }

  /**
   * Create a hash of user ID for correlation without exposing PII
   */
  private hashUserId(userId: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(`${userId}salt-for-logging`).digest('hex').substring(0, 16);
  }

  /**
   * Sanitize session ID for logging
   */
  private sanitizeSessionId(sessionId: string): string {
    // Only log first 8 characters of session ID
    return sessionId.substring(0, 8) + '*'.repeat(8);
  }

  /**
   * Determine if an event should be logged publicly
   */
  private shouldLogPublically(level: LogLevel, event: string): boolean {
    // Never log debug events publicly
    if (level === 'debug') return false;

    // Never log sensitive events publicly
    const sensitiveEvents = ['key_decrypt', 'credential_process', 'auth_token'];
    if (sensitiveEvents.some(sensitive => event.toLowerCase().includes(sensitive))) {
      return false;
    }

    return true;
  }

  /**
   * Create a public-safe version of a log entry
   */
  private createPublicLogEntry(entry: LogEntry): LogEntry {
    const publicEntry: LogEntry = {
      timestamp: entry.timestamp,
      level: entry.level,
      service: entry.service,
      event: entry.event
    };

    // Only add optional fields if they exist
    if (entry.session_id) publicEntry.session_id = entry.session_id;
    if (entry.user_id_hash) publicEntry.user_id_hash = entry.user_id_hash;
    if (entry.exchange) publicEntry.exchange = entry.exchange;
    if (entry.duration_ms) publicEntry.duration_ms = entry.duration_ms;
    if (entry.error_code) publicEntry.error_code = entry.error_code;
    if (entry.details) publicEntry.details = this.sanitizeForPublic(entry.details);

    return publicEntry;
  }

  /**
   * Additional sanitization for public logs
   */
  private sanitizeForPublic(details: Record<string, any>): Record<string, any> {
    const publicDetails: Record<string, any> = {};

    const allowedFields = [
      'count', 'status', 'method', 'path', 'status_code', 'response_time',
      'exchange', 'symbol', 'trade_count', 'volume', 'error_type'
    ];

    for (const [key, value] of Object.entries(details)) {
      if (allowedFields.includes(key.toLowerCase())) {
        publicDetails[key] = value;
      }
    }

    return publicDetails;
  }

  /**
   * Write log entry to file
   */
  private writeToFile(filePath: string, entry: LogEntry): void {
    try {
      const logLine = `${JSON.stringify(entry)}\n`;
      appendFileSync(filePath, logLine, 'utf8');
    } catch (error) {
      // Fallback to console if file writing fails
      console.error('Failed to write to log file:', error);
      console.log('LOG:', JSON.stringify(entry));
    }
  }
}

// Export singleton instance
export const logger = new SecureLogger();

// Export types and interfaces
export { SecureLogger };

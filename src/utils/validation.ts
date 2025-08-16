/**
 * Comprehensive validation utilities using Zod
 * Ensures all inputs are properly validated and sanitized
 */

import { z } from 'zod';
import { VALIDATION_PATTERNS } from '../constants.js';

// Base validation schemas
export const SessionIdSchema = z.string()
  .min(16, 'Session ID must be at least 16 characters')
  .max(128, 'Session ID too long')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Session ID contains invalid characters');

export const UserIdSchema = z.string()
  .min(1, 'User ID is required')
  .max(64, 'User ID too long')
  .regex(/^[a-zA-Z0-9._-]+$/, 'User ID contains invalid characters');

export const ExchangeNameSchema = z.enum([
  'binance', 'coinbase', 'kraken', 'okx', 'bybit', 'bitfinex',
  'huobi', 'kucoin', 'gate', 'mexc', 'bitget', 'bitstamp'
], {
  errorMap: () => ({ message: 'Unsupported exchange' })
});

export const Base64Schema = z.string()
  .regex(/^[A-Za-z0-9+/]*={0,2}$/, 'Invalid base64 format');

export const CredentialEnvelopeSchema = z.object({
  ephemeral_pub: Base64Schema,
  nonce: z.string().regex(/^[a-fA-F0-9]+$/, 'Invalid nonce format'),
  ciphertext: Base64Schema,
  tag: Base64Schema,
  metadata: z.object({
    exchange: ExchangeNameSchema,
    label: z.string().min(1).max(64),
    ttl: z.number().min(300).max(604800).default(86400)
  })
});

export class ValidationUtils {
  /**
   * Validate encrypted payload using Zod
   */
  static validateEncryptedPayload(payload: unknown): { valid: boolean; errors: string[]; data?: any } {
    try {
      const validated = CredentialEnvelopeSchema.parse(payload);
      return { valid: true, errors: [], data: validated };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          valid: false,
          errors: error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`)
        };
      }
      return { valid: false, errors: ['Unknown validation error'] };
    }
  }

  /**
   * Validate base64 encoding
   */
  static isValidBase64(str: string): boolean {
    return VALIDATION_PATTERNS.BASE64.test(str);
  }

  /**
   * Validate UUID format
   */
  static isValidUuid(str: string): boolean {
    return VALIDATION_PATTERNS.UUID.test(str);
  }

  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    return VALIDATION_PATTERNS.EMAIL.test(email);
  }

  /**
   * Validate session ID format
   */
  static isValidSessionId(sessionId: string): boolean {
    return VALIDATION_PATTERNS.SESSION_ID.test(sessionId);
  }

  /**
   * Validate TTL value
   */
  static isValidTtl(ttl: number, minSeconds: number, maxSeconds: number): boolean {
    return Number.isInteger(ttl) && ttl >= minSeconds && ttl <= maxSeconds;
  }

  /**
   * Sanitize string input
   */
  static sanitizeString(input: string, maxLength: number = 255): string {
    return input.trim().substring(0, maxLength);
  }

  /**
   * Validate exchange name
   */
  static isValidExchange(exchange: string): boolean {
    const validExchanges = ['binance', 'coinbase', 'kraken', 'bybit', 'okx'];
    return validExchanges.includes(exchange.toLowerCase());
  }

  /**
   * Legacy validation method (deprecated - use Zod version above)
   */
  static validateEncryptedPayloadLegacy(payload: any): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!payload.ephemeral_pub || !this.isValidBase64(payload.ephemeral_pub)) {
      errors.push('Invalid ephemeral_pub format');
    }

    if (!payload.nonce || !this.isValidBase64(payload.nonce)) {
      errors.push('Invalid nonce format');
    }

    if (!payload.ciphertext || !this.isValidBase64(payload.ciphertext)) {
      errors.push('Invalid ciphertext format');
    }

    if (!payload.tag || !this.isValidBase64(payload.tag)) {
      errors.push('Invalid tag format');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

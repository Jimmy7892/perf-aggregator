/**
 * Validation utilities
 */

import { VALIDATION_PATTERNS } from '../constants.js';

export class ValidationUtils {
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
   * Validate encrypted payload structure
   */
  static validateEncryptedPayload(payload: any): {
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
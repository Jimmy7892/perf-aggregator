/**
 * Crypto utilities
 */

import { randomBytes } from 'crypto';
import { CRYPTO_CONFIG } from '../constants.js';

export class CryptoUtils {
  /**
   * Generate cryptographically secure random bytes
   */
  static generateRandomBytes(size: number): Uint8Array {
    return new Uint8Array(randomBytes(size));
  }

  /**
   * Generate a secure nonce for encryption
   */
  static generateNonce(): Uint8Array {
    return this.generateRandomBytes(CRYPTO_CONFIG.NONCE_SIZE);
  }

  /**
   * Generate a secure salt for key derivation
   */
  static generateSalt(): Uint8Array {
    return this.generateRandomBytes(CRYPTO_CONFIG.SALT_SIZE);
  }

  /**
   * Convert ArrayBuffer to base64 string
   */
  static arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to ArrayBuffer
   */
  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Securely zero array buffer
   */
  static secureZero(buffer: ArrayBuffer | Uint8Array): void {
    const view = new Uint8Array(buffer);
    view.fill(0);
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  static constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Generate a secure session ID
   */
  static generateSessionId(): string {
    const randomBytes = this.generateRandomBytes(16);
    return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Validate cryptographic key format
   */
  static isValidKeyFormat(key: string, expectedLength?: number): boolean {
    try {
      const decoded = atob(key);
      if (expectedLength && decoded.length !== expectedLength) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Create info string for HKDF key derivation
   */
  static createHkdfInfo(context: string, version: string = 'v1'): Uint8Array {
    const info = `${context}-${version}`;
    return new TextEncoder().encode(info);
  }
}
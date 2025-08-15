/**
 * WebCrypto Client Helper for Secure Key Exchange
 * 
 * SECURITY: This implements X25519 ECDH + AES-GCM encryption for client-side
 * credential encryption before sending to the enclave.
 * 
 * Flow:
 * 1. Client verifies enclave attestation (mock verification in dev)
 * 2. Client generates ephemeral X25519 key pair
 * 3. Client performs ECDH with enclave public key
 * 4. Client derives AES-GCM key using HKDF
 * 5. Client encrypts credentials and sends to enclave
 */

import type {
  AttestationQuote,
  EncryptedPayload,
  Credentials,
  AttestationVerificationResult
} from '../types/index.js';
import { CRYPTO_CONFIG } from '../constants.js';
import { CryptoUtils } from '../utils/crypto.js';

export class CryptoHelper {
  private static readonly CURVE = CRYPTO_CONFIG.CURVE;
  private static readonly AES_ALGORITHM = CRYPTO_CONFIG.AES_ALGORITHM;
  private static readonly HKDF_ALGORITHM = CRYPTO_CONFIG.HKDF_ALGORITHM;
  private static readonly HASH_ALGORITHM = CRYPTO_CONFIG.HASH_ALGORITHM;

  /**
   * Verify enclave attestation quote
   * 
   * SECURITY: In production, this must verify:
   * - Quote signature against vendor CA (Intel/AWS/etc.)
   * - Enclave measurement matches expected value
   * - Security flags are appropriate
   * 
   * @param quote Attestation quote from enclave
   * @param expectedImageHash Expected hash of enclave image
   * @returns true if attestation is valid
   */
  static async verifyAttestation(
    quote: AttestationQuote, 
    expectedImageHash: string
  ): Promise<AttestationVerificationResult> {
    try {
      // DEVELOPMENT ONLY: Mock verification
      // In production, implement proper quote verification
      if (quote.image_hash === expectedImageHash) {
        console.log('✅ Mock attestation verification passed (DEV ONLY)');
        return { valid: true };
      } else {
        console.warn('❌ Mock attestation verification failed: image hash mismatch');
        return { 
          valid: false, 
          error: `Image hash mismatch. Expected: ${expectedImageHash}, Got: ${quote.image_hash}` 
        };
      }
    } catch (error) {
      return { 
        valid: false, 
        error: error instanceof Error ? error.message : 'Unknown verification error' 
      };
    }
  }

  /**
   * Encrypt credentials using X25519 ECDH + AES-GCM
   * 
   * @param credentials User credentials to encrypt
   * @param enclavePubKeyB64 Enclave's X25519 public key (base64)
   * @returns Encrypted payload ready for transmission
   */
  static async encryptCredentials(
    credentials: Credentials,
    enclavePubKeyB64: string
  ): Promise<EncryptedPayload> {
    try {
      // 1. Generate ephemeral key pair for ECDH
      const ephemeralKeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'X25519'
        },
        false, // not extractable for security
        ['deriveKey']
      );

      // 2. Export ephemeral public key
      const ephemeralPubKeyRaw = await crypto.subtle.exportKey(
        'raw',
        ephemeralKeyPair.publicKey
      );
      const ephemeralPubKeyB64 = this.arrayBufferToBase64(ephemeralPubKeyRaw);

      // 3. Import enclave public key
      const enclavePubKeyRaw = this.base64ToArrayBuffer(enclavePubKeyB64);
      const enclavePubKey = await crypto.subtle.importKey(
        'raw',
        enclavePubKeyRaw,
        {
          name: 'ECDH',
          namedCurve: 'X25519'
        },
        false,
        []
      );

      // 4. Perform ECDH to get shared secret
      const sharedSecret = await crypto.subtle.deriveKey(
        {
          name: 'ECDH',
          public: enclavePubKey
        },
        ephemeralKeyPair.privateKey,
        {
          name: this.HKDF_ALGORITHM,
          hash: this.HASH_ALGORITHM,
          length: 256
        },
        false,
        ['deriveKey']
      );

      // 5. Derive AES-GCM key from shared secret using HKDF
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const info = new TextEncoder().encode('enclave-credentials-v1');
      
      const aesKey = await crypto.subtle.deriveKey(
        {
          name: this.HKDF_ALGORITHM,
          hash: this.HASH_ALGORITHM,
          salt: salt,
          info: info
        },
        sharedSecret,
        {
          name: this.AES_ALGORITHM,
          length: 256
        },
        false,
        ['encrypt']
      );

      // 6. Generate random nonce
      const nonce = crypto.getRandomValues(new Uint8Array(12));

      // 7. Encrypt credentials
      const credentialsJson = JSON.stringify(credentials);
      const credentialsBuffer = new TextEncoder().encode(credentialsJson);

      const encryptResult = await crypto.subtle.encrypt(
        {
          name: this.AES_ALGORITHM,
          iv: nonce
        },
        aesKey,
        credentialsBuffer
      );

      // 8. Extract ciphertext and auth tag
      const encryptedArray = new Uint8Array(encryptResult);
      const ciphertext = encryptedArray.slice(0, -16); // All but last 16 bytes
      const tag = encryptedArray.slice(-16); // Last 16 bytes

      // 9. Securely zero sensitive data
      credentialsBuffer.fill(0);

      return {
        ephemeral_pub: ephemeralPubKeyB64,
        nonce: this.arrayBufferToBase64(nonce),
        ciphertext: this.arrayBufferToBase64(ciphertext),
        tag: this.arrayBufferToBase64(tag)
      };

    } catch (error) {
      throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Verify signature of aggregated results
   * 
   * @param aggregatesJson Canonical JSON of aggregates
   * @param signatureB64 Base64 encoded signature
   * @param enclavePubKeyB64 Enclave's signing public key
   * @returns true if signature is valid
   */
  static async verifyAggregateSignature(
    aggregatesJson: string,
    signatureB64: string,
    enclavePubKeyB64: string
  ): Promise<boolean> {
    try {
      // Import enclave public key for verification
      const pubKeyRaw = this.base64ToArrayBuffer(enclavePubKeyB64);
      const pubKey = await crypto.subtle.importKey(
        'raw',
        pubKeyRaw,
        {
          name: 'Ed25519'
        },
        false,
        ['verify']
      );

      // Verify signature
      const signature = this.base64ToArrayBuffer(signatureB64);
      const message = new TextEncoder().encode(aggregatesJson);

      const isValid = await crypto.subtle.verify(
        'Ed25519',
        pubKey,
        signature,
        message
      );

      return isValid;

    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  /**
   * Generate a secure session ID for tracking
   */
  static generateSessionId(): string {
    return CryptoUtils.generateSessionId();
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  static constantTimeEquals(a: string, b: string): boolean {
    return CryptoUtils.constantTimeEquals(a, b);
  }

  // Utility functions
  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    return CryptoUtils.arrayBufferToBase64(buffer);
  }

  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    return CryptoUtils.base64ToArrayBuffer(base64);
  }

  /**
   * Securely zero array buffer
   */
  static secureZero(buffer: ArrayBuffer | Uint8Array): void {
    CryptoUtils.secureZero(buffer);
  }
}

/**
 * Example usage:
 * 
 * ```typescript
 * // 1. Get attestation from enclave
 * const response = await fetch('/attestation/quote');
 * const attestation = await response.json();
 * 
 * // 2. Verify attestation
 * const verification = await CryptoHelper.verifyAttestation(
 *   attestation, 
 *   'expected-image-hash'
 * );
 * 
 * if (!verification.valid) {
 *   throw new Error(`Attestation verification failed: ${verification.error}`);
 * }
 * 
 * // 3. Encrypt credentials
 * const credentials = {
 *   exchange: 'binance',
 *   apiKey: 'your-api-key',
 *   apiSecret: 'your-api-secret',
 *   sandbox: false
 * };
 * 
 * const encrypted = await CryptoHelper.encryptCredentials(
 *   credentials,
 *   attestation.enclave_pubkey
 * );
 * 
 * // 4. Submit to enclave
 * const submitResponse = await fetch('/enclave/submit_key', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({
 *     ...encrypted,
 *     metadata: {
 *       exchange: credentials.exchange,
 *       label: 'main-account',
 *       ttl: 3600
 *     }
 *   })
 * });
 * ```
 */
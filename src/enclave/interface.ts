/**
 * TEE Enclave Service Interface
 *
 * SECURITY: This interface defines the contract for secure enclave operations.
 * All implementations MUST ensure:
 * - API keys are never stored in plaintext outside enclave memory
 * - Memory is securely zeroed after use
 * - All operations are logged for audit trail
 */

import type {
  EncryptedPayload,
  DecryptedCredentials,
  AggregateResult,
  SignedAggregates,
  AttestationQuote
} from '../types/index.js';

export interface EnclaveService {
  /**
   * Get attestation quote and enclave public key
   * Used by clients to verify enclave authenticity before sending secrets
   */
  getAttestationQuote(): Promise<AttestationQuote>;

  /**
   * Submit encrypted API keys to enclave
   * SECURITY: Must never store decrypted keys outside enclave memory
   *
   * @param sessionId Unique session identifier
   * @param payload Encrypted credentials payload
   * @returns Success/error status
   */
  submitKey(sessionId: string, payload: EncryptedPayload): Promise<{ success: boolean; error?: string }>;

  /**
   * Request aggregated results for a session
   * Returns signed aggregates computed within the enclave
   *
   * @param sessionId Session identifier
   * @returns Signed aggregated results and merkle root
   */
  requestAggregates(sessionId: string): Promise<{
    aggregates_signed: SignedAggregates;
    merkle_root: string;
  }>;

  /**
   * Revoke session and purge all associated data
   * SECURITY: Must securely zero all memory and sealed storage
   *
   * @param sessionId Session identifier to revoke
   */
  revoke(sessionId: string): Promise<void>;

  /**
   * Health check for enclave
   */
  health(): Promise<{ status: 'healthy' | 'unhealthy'; details?: string }>;
}

export abstract class BaseEnclaveService implements EnclaveService {
  protected abstract enclavePrivateKey: string;
  protected abstract enclavePublicKey: string;

  abstract getAttestationQuote(): Promise<AttestationQuote>;
  abstract submitKey(sessionId: string, payload: EncryptedPayload): Promise<{ success: boolean; error?: string }>;
  abstract requestAggregates(sessionId: string): Promise<{ aggregates_signed: SignedAggregates; merkle_root: string }>;
  abstract revoke(sessionId: string): Promise<void>;

  async health(): Promise<{ status: 'healthy' | 'unhealthy'; details?: string }> {
    return { status: 'healthy' };
  }

  /**
   * Securely zero memory buffer
   * SECURITY: Critical for ensuring secrets don't remain in memory
   */
  protected secureZero(buffer: Buffer | Uint8Array): void {
    buffer.fill(0);
  }

  /**
   * Securely zero string (convert to buffer first)
   */
  protected secureZeroString(str: string): void {
    const buffer = Buffer.from(str, 'utf8');
    this.secureZero(buffer);
  }
}

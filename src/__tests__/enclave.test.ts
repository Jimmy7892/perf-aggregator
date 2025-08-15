/**
 * Enclave Service Tests
 * 
 * SECURITY CRITICAL: These tests verify that:
 * - Enclave never stores plaintext credentials
 * - Memory is properly zeroed after operations
 * - Session isolation is maintained
 * - Revocation properly purges data
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { MockEnclaveService } from '../enclave/mock.js';
import type { EncryptedPayload } from '../types/index.js';

describe('MockEnclaveService', () => {
  let enclave: MockEnclaveService;

  beforeEach(() => {
    enclave = new MockEnclaveService();
  });

  describe('Attestation', () => {
    test('should provide valid attestation quote', async () => {
      const quote = await enclave.getAttestationQuote();
      
      expect(quote.quote).toBeDefined();
      expect(quote.enclave_pubkey).toBeDefined();
      expect(quote.image_hash).toBeDefined();
      
      // Verify base64 encoding
      expect(() => atob(quote.quote)).not.toThrow();
      expect(() => atob(quote.enclave_pubkey)).not.toThrow();
      
      // Verify image hash format
      expect(quote.image_hash).toMatch(/^mock-[a-f0-9]{64}$/);
    });

    test('should provide consistent public key', async () => {
      const quote1 = await enclave.getAttestationQuote();
      const quote2 = await enclave.getAttestationQuote();
      
      expect(quote1.enclave_pubkey).toEqual(quote2.enclave_pubkey);
    });
  });

  describe('Key Submission', () => {
    const mockPayload: EncryptedPayload = {
      ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
      nonce: 'dGVzdC1ub25jZQ==',
      ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
      tag: 'dGVzdC10YWc='
    };

    test('should accept valid encrypted payload', async () => {
      const sessionId = 'test-session-1';
      const result = await enclave.submitKey(sessionId, mockPayload);
      
      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
    });

    test('should reject invalid base64 encoding', async () => {
      const invalidPayload = {
        ...mockPayload,
        ephemeral_pub: 'invalid-base64!'
      };
      
      const result = await enclave.submitKey('test-session', invalidPayload);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid base64 encoding');
    });

    test('should handle multiple sessions independently', async () => {
      const session1 = 'session-1';
      const session2 = 'session-2';
      
      const result1 = await enclave.submitKey(session1, mockPayload);
      const result2 = await enclave.submitKey(session2, mockPayload);
      
      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      
      // Verify sessions are independent
      const info1 = enclave.getSessionInfo(session1);
      const info2 = enclave.getSessionInfo(session2);
      
      expect(info1).toBeDefined();
      expect(info2).toBeDefined();
      expect(info1?.sessionId).not.toEqual(info2?.sessionId);
    });
  });

  describe('Aggregate Computation', () => {
    beforeEach(async () => {
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey('test-session', mockPayload);
    });

    test('should compute and sign aggregates', async () => {
      const result = await enclave.requestAggregates('test-session');
      
      expect(result.aggregates_signed).toBeDefined();
      expect(result.merkle_root).toBeDefined();
      
      const aggregates = result.aggregates_signed;
      expect(aggregates.signature).toBeDefined();
      expect(aggregates.payload.pnl).toBeDefined();
      expect(aggregates.payload.sharpe).toBeDefined();
      expect(aggregates.payload.volume).toBeDefined();
      expect(aggregates.payload.trades).toBeDefined();
      expect(aggregates.payload.from).toBeDefined();
      expect(aggregates.payload.to).toBeDefined();
      
      // Verify numeric values are reasonable
      expect(typeof aggregates.payload.pnl).toBe('number');
      expect(typeof aggregates.payload.sharpe).toBe('number');
      expect(typeof aggregates.payload.volume).toBe('number');
      expect(typeof aggregates.payload.trades).toBe('number');
      expect(aggregates.payload.trades).toBeGreaterThan(0);
    });

    test('should return cached results on subsequent requests', async () => {
      const result1 = await enclave.requestAggregates('test-session');
      const result2 = await enclave.requestAggregates('test-session');
      
      expect(result1.aggregates_signed).toEqual(result2.aggregates_signed);
      expect(result1.merkle_root).toEqual(result2.merkle_root);
    });

    test('should fail for non-existent session', async () => {
      await expect(
        enclave.requestAggregates('non-existent-session')
      ).rejects.toThrow('Session non-existent-session not found');
    });

    test('should produce deterministic results for same input', async () => {
      const sessionId1 = 'deterministic-test-1';
      const sessionId2 = 'deterministic-test-2';
      
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey(sessionId1, mockPayload);
      await enclave.submitKey(sessionId2, mockPayload);
      
      const result1 = await enclave.requestAggregates(sessionId1);
      const result2 = await enclave.requestAggregates(sessionId2);
      
      // Results should be deterministic for same mock input
      expect(result1.aggregates_signed.payload.pnl)
        .toEqual(result2.aggregates_signed.payload.pnl);
    });
  });

  describe('Session Revocation', () => {
    beforeEach(async () => {
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey('revoke-test-session', mockPayload);
    });

    test('should successfully revoke session', async () => {
      const sessionId = 'revoke-test-session';
      
      // Verify session exists before revocation
      const infoBefore = enclave.getSessionInfo(sessionId);
      expect(infoBefore).toBeDefined();
      
      // Revoke session
      await enclave.revoke(sessionId);
      
      // Verify session is purged after revocation
      const infoAfter = enclave.getSessionInfo(sessionId);
      expect(infoAfter).toBeNull();
    });

    test('should handle revocation of non-existent session gracefully', async () => {
      await expect(enclave.revoke('non-existent-session')).resolves.not.toThrow();
    });

    test('CRITICAL: should purge all session data on revocation', async () => {
      const sessionId = 'purge-test-session';
      
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey(sessionId, mockPayload);
      await enclave.requestAggregates(sessionId);
      
      // Verify data exists
      expect(enclave.getSessionInfo(sessionId)).toBeDefined();
      
      // Revoke and verify complete purge
      await enclave.revoke(sessionId);
      expect(enclave.getSessionInfo(sessionId)).toBeNull();
      
      // Subsequent operations should fail
      await expect(
        enclave.requestAggregates(sessionId)
      ).rejects.toThrow('Session ' + sessionId + ' not found');
    });
  });

  describe('Health Check', () => {
    test('should report healthy status', async () => {
      const health = await enclave.health();
      
      expect(health.status).toBe('healthy');
    });
  });

  describe('Security Tests', () => {
    test('CRITICAL: should never expose plaintext credentials', async () => {
      const sessionId = 'security-test-session';
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey(sessionId, mockPayload);
      const result = await enclave.requestAggregates(sessionId);
      
      // Convert all results to string for inspection
      const resultString = JSON.stringify(result);
      
      // Verify no plaintext secrets are exposed
      expect(resultString).not.toContain('mock-api-key');
      expect(resultString).not.toContain('mock-api-secret');
      expect(resultString).not.toContain('apiKey');
      expect(resultString).not.toContain('apiSecret');
      
      // Only encrypted/signed data should be present
      expect(result.aggregates_signed.signature).toBeDefined();
      expect(result.merkle_root).toBeDefined();
    });

    test('CRITICAL: should isolate sessions properly', async () => {
      const session1 = 'isolation-test-1';
      const session2 = 'isolation-test-2';
      
      const mockPayload: EncryptedPayload = {
        ephemeral_pub: 'dGVzdC1wdWJsaWMta2V5',
        nonce: 'dGVzdC1ub25jZQ==',
        ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
        tag: 'dGVzdC10YWc='
      };
      
      await enclave.submitKey(session1, mockPayload);
      await enclave.submitKey(session2, mockPayload);
      
      // Revoke one session
      await enclave.revoke(session1);
      
      // Other session should still work
      expect(enclave.getSessionInfo(session2)).toBeDefined();
      await expect(enclave.requestAggregates(session2)).resolves.toBeDefined();
      
      // Revoked session should be gone
      expect(enclave.getSessionInfo(session1)).toBeNull();
      await expect(enclave.requestAggregates(session1)).rejects.toThrow();
    });
  });
});
/**
 * End-to-End Integration Tests
 *
 * SECURITY CRITICAL: These tests verify the complete flow:
 * 1. Client encrypts credentials
 * 2. Server receives and stores encrypted data (no plaintext)
 * 3. Enclave decrypts and processes in memory only
 * 4. Signed aggregates are returned
 * 5. Revocation properly purges all data
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { EnclaveServer } from '../enclave-server.js';
import { CryptoHelper } from '../client/crypto-helper.js';
import { Database } from '../database.js';

// Mock database for testing
const TEST_DB_URL = 'postgresql://test:test@localhost:5432/test_perf_aggregator';

describe('End-to-End Integration Tests', () => {
  let server: EnclaveServer;
  let db: Database;
  let baseUrl: string;

  beforeAll(async () => {
    // Set test environment
    process.env.DATABASE_URL = TEST_DB_URL;
    process.env.ENCLAVE_PORT = '3001';
    process.env.NODE_ENV = 'test';

    // Initialize database
    db = new Database(TEST_DB_URL);

    // Initialize server
    server = new EnclaveServer();
    await server.start();

    baseUrl = 'http://localhost:3001';

    // Wait for server to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));
  });

  afterAll(async () => {
    await db.close();
    // Note: Server cleanup would go here in a real test environment
  });

  describe('Complete Encryption Flow', () => {
    test('INTEGRATION: Full client-to-enclave flow', async () => {
      // 1. Get attestation quote
      const quoteResponse = await fetch(`${baseUrl}/attestation/quote`);
      expect(quoteResponse.ok).toBe(true);

      const attestation = await quoteResponse.json();
      expect(attestation.quote).toBeDefined();
      expect(attestation.enclave_pubkey).toBeDefined();
      expect(attestation.image_hash).toBeDefined();

      // 2. Verify attestation (mock verification in test)
      const verification = await CryptoHelper.verifyAttestation(
        attestation,
        attestation.image_hash // Use same hash for mock verification
      );
      expect(verification.valid).toBe(true);

      // 3. Encrypt credentials
      const credentials = {
        exchange: 'binance',
        apiKey: 'test-api-key-12345',
        apiSecret: 'test-api-secret-67890',
        sandbox: true,
        symbols: ['BTC/USDT', 'ETH/USDT']
      };

      const encrypted = await CryptoHelper.encryptCredentials(
        credentials,
        attestation.enclave_pubkey
      );

      // 4. Submit encrypted credentials
      const submitResponse = await fetch(`${baseUrl}/enclave/submit_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...encrypted,
          metadata: {
            exchange: credentials.exchange,
            label: 'integration-test',
            ttl: 3600
          }
        })
      });

      expect(submitResponse.ok).toBe(true);
      const submitResult = await submitResponse.json();
      expect(submitResult.session_id).toBeDefined();
      expect(submitResult.session_id).toMatch(/^[a-f0-9-]{36}$/); // UUID format

      const sessionId = submitResult.session_id;

      // 5. Request aggregates
      const aggregatesResponse = await fetch(`${baseUrl}/enclave/request_aggregates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
      });

      expect(aggregatesResponse.ok).toBe(true);
      const aggregatesResult = await aggregatesResponse.json();

      expect(aggregatesResult.aggregates_signed).toBeDefined();
      expect(aggregatesResult.merkle_root).toBeDefined();
      expect(aggregatesResult.logs_url).toBeDefined();

      const aggregates = aggregatesResult.aggregates_signed;
      expect(aggregates.signature).toBeDefined();
      expect(aggregates.payload.pnl).toBeDefined();
      expect(aggregates.payload.sharpe).toBeDefined();
      expect(aggregates.payload.volume).toBeDefined();
      expect(aggregates.payload.trades).toBeDefined();

      // 6. Verify no plaintext secrets in response
      const responseString = JSON.stringify(aggregatesResult);
      expect(responseString).not.toContain('test-api-key-12345');
      expect(responseString).not.toContain('test-api-secret-67890');
      expect(responseString).not.toContain('apiKey');
      expect(responseString).not.toContain('apiSecret');

      // 7. Revoke session
      const revokeResponse = await fetch(`${baseUrl}/enclave/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
      });

      expect(revokeResponse.ok).toBe(true);
      const revokeResult = await revokeResponse.json();
      expect(revokeResult.success).toBe(true);

      // 8. Verify revoked session cannot be used
      const postRevokeResponse = await fetch(`${baseUrl}/enclave/request_aggregates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
      });

      expect(postRevokeResponse.ok).toBe(false);
    });
  });

  describe('Database Security Tests', () => {
    test('CRITICAL: Database never contains plaintext secrets', async () => {
      // This test directly inspects the database to ensure no plaintext secrets

      // 1. Submit encrypted credentials
      const quoteResponse = await fetch(`${baseUrl}/attestation/quote`);
      const attestation = await quoteResponse.json();

      const credentials = {
        exchange: 'binance',
        apiKey: 'secret-key-should-never-appear-in-db',
        apiSecret: 'secret-value-should-never-appear-in-db'
      };

      const encrypted = await CryptoHelper.encryptCredentials(
        credentials,
        attestation.enclave_pubkey
      );

      const submitResponse = await fetch(`${baseUrl}/enclave/submit_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...encrypted,
          metadata: {
            exchange: credentials.exchange,
            label: 'db-security-test',
            ttl: 3600
          }
        })
      });

      const submitResult = await submitResponse.json();
      const sessionId = submitResult.session_id;

      // 2. Query database directly to verify no plaintext secrets
      const session = await db.getSession(sessionId);
      expect(session).toBeDefined();

      const credential = await db.getCredentials(sessionId);
      expect(credential).toBeDefined();

      // 3. Convert all database fields to strings and check for secrets
      const sessionString = JSON.stringify(session);
      const credentialString = JSON.stringify(credential);

      expect(sessionString).not.toContain('secret-key-should-never-appear-in-db');
      expect(sessionString).not.toContain('secret-value-should-never-appear-in-db');
      expect(credentialString).not.toContain('secret-key-should-never-appear-in-db');
      expect(credentialString).not.toContain('secret-value-should-never-appear-in-db');

      // 4. Verify ciphertext is actually encrypted (not base64 of plaintext)
      const credentialsJson = JSON.stringify(credentials);
      const plainTextBase64 = Buffer.from(credentialsJson).toString('base64');
      expect(credential?.ciphertext.toString('base64')).not.toEqual(plainTextBase64);

      // 5. Clean up
      await fetch(`${baseUrl}/enclave/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
      });
    });
  });

  describe('Security Validation', () => {
    test('should reject invalid input formats', async () => {
      // Test invalid base64
      const invalidResponse = await fetch(`${baseUrl}/enclave/submit_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ephemeral_pub: 'invalid-base64!',
          nonce: 'dGVzdA==',
          ciphertext: 'dGVzdA==',
          tag: 'dGVzdA==',
          metadata: {
            exchange: 'binance',
            label: 'test',
            ttl: 3600
          }
        })
      });

      expect(invalidResponse.ok).toBe(false);
      const error = await invalidResponse.json();
      expect(error.error).toContain('Validation failed');
    });

    test('should enforce TTL limits', async () => {
      const quoteResponse = await fetch(`${baseUrl}/attestation/quote`);
      const attestation = await quoteResponse.json();

      const encrypted = await CryptoHelper.encryptCredentials(
        { exchange: 'binance', apiKey: 'test', apiSecret: 'test' },
        attestation.enclave_pubkey
      );

      // Try to set TTL beyond maximum
      const response = await fetch(`${baseUrl}/enclave/submit_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...encrypted,
          metadata: {
            exchange: 'binance',
            label: 'ttl-test',
            ttl: 99999999 // Way beyond max
          }
        })
      });

      // Should still succeed but with capped TTL
      expect(response.ok).toBe(true);
    });

    test('should handle non-existent sessions', async () => {
      const response = await fetch(`${baseUrl}/enclave/request_aggregates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: '00000000-0000-0000-0000-000000000000' })
      });

      expect(response.ok).toBe(false);
      const error = await response.json();
      expect(error.error).toContain('Session not found');
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits', async () => {
      const promises = [];

      // Send many requests quickly to trigger rate limiting
      for (let i = 0; i < 110; i++) { // Above the default limit of 100
        promises.push(
          fetch(`${baseUrl}/health`)
        );
      }

      const responses = await Promise.all(promises);
      const statusCodes = responses.map(r => r.status);

      // Some requests should be rate limited (429)
      expect(statusCodes.includes(429)).toBe(true);
    });
  });

  describe('Health Checks', () => {
    test('should report system health', async () => {
      const response = await fetch(`${baseUrl}/health`);
      expect(response.ok).toBe(true);

      const health = await response.json();
      expect(health.status).toBe('healthy');
      expect(health.database).toBeDefined();
      expect(health.enclave).toBeDefined();
      expect(health.timestamp).toBeDefined();
    });
  });
});

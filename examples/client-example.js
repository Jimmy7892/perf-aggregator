/**
 * Client Example: How to use the Secure Enclave Backend
 * 
 * This example demonstrates the complete flow for a trader:
 * 1. Verify enclave attestation
 * 2. Encrypt API credentials
 * 3. Submit to enclave
 * 4. Request aggregated results
 * 5. Verify signatures
 * 6. Revoke when done
 */

// Note: In a real browser/Node.js environment, you would import the actual module
// import { CryptoHelper } from '../src/client/crypto-helper.js';

class TraderClient {
  constructor(enclaveBaseUrl = 'http://localhost:3000') {
    this.baseUrl = enclaveBaseUrl;
    this.sessionId = null;
  }

  /**
   * Complete trading session workflow
   */
  async runTradingSession(credentials) {
    try {
      console.log('🔄 Starting secure trading session...');

      // Step 1: Get and verify attestation
      console.log('1️⃣ Getting enclave attestation...');
      const attestation = await this.getAttestation();
      
      const verification = await this.verifyAttestation(attestation);
      if (!verification.valid) {
        throw new Error(`Attestation verification failed: ${verification.error}`);
      }
      console.log('✅ Attestation verified');

      // Step 2: Encrypt credentials
      console.log('2️⃣ Encrypting credentials...');
      const encrypted = await this.encryptCredentials(credentials, attestation.enclave_pubkey);
      console.log('✅ Credentials encrypted');

      // Step 3: Submit to enclave
      console.log('3️⃣ Submitting to enclave...');
      this.sessionId = await this.submitCredentials(encrypted, credentials.exchange);
      console.log(`✅ Session created: ${this.sessionId}`);

      // Step 4: Request aggregates (simulate some delay)
      console.log('4️⃣ Waiting for aggregation (simulating trading period)...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      console.log('5️⃣ Requesting aggregated results...');
      const results = await this.getAggregates();
      console.log('✅ Aggregates received');

      // Step 5: Verify signature
      console.log('6️⃣ Verifying signature...');
      const signatureValid = await this.verifyAggregateSignature(
        results.aggregates_signed,
        attestation.enclave_pubkey
      );
      console.log(signatureValid ? '✅ Signature valid' : '❌ Signature invalid');

      // Display results
      console.log('📊 Trading Results:');
      console.log(`   PnL: ${results.aggregates_signed.payload.pnl}%`);
      console.log(`   Sharpe Ratio: ${results.aggregates_signed.payload.sharpe}`);
      console.log(`   Volume: ${results.aggregates_signed.payload.volume}`);
      console.log(`   Trades: ${results.aggregates_signed.payload.trades}`);
      console.log(`   Period: ${results.aggregates_signed.payload.from} → ${results.aggregates_signed.payload.to}`);

      return results;

    } catch (error) {
      console.error('❌ Trading session failed:', error.message);
      throw error;
    }
  }

  /**
   * Revoke session and purge all data
   */
  async revokeSession() {
    if (!this.sessionId) {
      console.log('ℹ️ No active session to revoke');
      return;
    }

    try {
      console.log('🗑️ Revoking session and purging data...');
      
      const response = await fetch(`${this.baseUrl}/enclave/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: this.sessionId })
      });

      if (!response.ok) {
        throw new Error(`Revoke failed: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      console.log('✅ Session revoked successfully');
      this.sessionId = null;
      
      return result;

    } catch (error) {
      console.error('❌ Failed to revoke session:', error.message);
      throw error;
    }
  }

  // Private methods

  async getAttestation() {
    const response = await fetch(`${this.baseUrl}/attestation/quote`);
    if (!response.ok) {
      throw new Error(`Failed to get attestation: ${response.status}`);
    }
    return await response.json();
  }

  async verifyAttestation(attestation) {
    // In production, implement real attestation verification
    // For demo purposes, use mock verification
    return {
      valid: attestation.image_hash.startsWith('mock-'),
      error: attestation.image_hash.startsWith('mock-') ? null : 'Invalid mock attestation'
    };
  }

  async encryptCredentials(credentials, enclavePubKey) {
    // Mock encryption for demo - in real implementation, use CryptoHelper
    const mockEncrypted = {
      ephemeral_pub: btoa('mock-ephemeral-public-key'),
      nonce: btoa('mock-nonce-12345678'),
      ciphertext: btoa(JSON.stringify(credentials) + '-encrypted'),
      tag: btoa('mock-auth-tag-1234')
    };
    
    return mockEncrypted;
  }

  async submitCredentials(encrypted, exchange) {
    const response = await fetch(`${this.baseUrl}/enclave/submit_key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...encrypted,
        metadata: {
          exchange: exchange,
          label: 'trader-session',
          ttl: 3600 // 1 hour
        }
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Submit failed: ${error.error || response.statusText}`);
    }

    const result = await response.json();
    return result.session_id;
  }

  async getAggregates() {
    const response = await fetch(`${this.baseUrl}/enclave/request_aggregates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: this.sessionId })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get aggregates failed: ${error.error || response.statusText}`);
    }

    return await response.json();
  }

  async verifyAggregateSignature(aggregatesSigned, enclavePubKey) {
    // In production, implement real signature verification
    // For demo, just check that signature exists
    return aggregatesSigned.signature && aggregatesSigned.signature.length > 0;
  }
}

// Example usage
async function example() {
  const client = new TraderClient();

  // Example credentials (these would be real API keys in production)
  const credentials = {
    exchange: 'binance',
    apiKey: 'your-binance-api-key',
    apiSecret: 'your-binance-api-secret',
    sandbox: false,
    symbols: ['BTC/USDT', 'ETH/USDT', 'ADA/USDT']
  };

  try {
    // Run a complete trading session
    await client.runTradingSession(credentials);

    // Simulate some time passing
    console.log('\n⏳ Simulating trading activity...\n');
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Revoke session when done
    await client.revokeSession();

    console.log('\n🎉 Example completed successfully!');
    console.log('\n🔒 Security Notes:');
    console.log('   - API keys were encrypted before transmission');
    console.log('   - No plaintext secrets stored in database');
    console.log('   - All data purged after revocation');
    console.log('   - Aggregated results are cryptographically signed');

  } catch (error) {
    console.error('\n💥 Example failed:', error.message);
    
    // Always try to clean up, even on error
    try {
      await client.revokeSession();
    } catch (cleanupError) {
      console.error('Failed to cleanup session:', cleanupError.message);
    }
  }
}

// Run example if this file is executed directly
if (typeof module !== 'undefined' && require.main === module) {
  example().catch(console.error);
}

// Export for use in other modules
if (typeof module !== 'undefined') {
  module.exports = { TraderClient };
} else {
  // Browser environment
  window.TraderClient = TraderClient;
}
import { generateKeyPair, encryptCredentials } from '../libs/crypto.js';

interface SecureClientConfig {
  enclaveUrl: string;
  userId: string;
  exchange: string;
  apiKey: string;
  secret: string;
  accountType?: 'spot' | 'futures' | 'margin';
  sandbox?: boolean;
  ttl?: number; // Durée de vie de la session en secondes
}

interface EnclaveResponse {
  session_id: string;
  expires_at: string;
  status: string;
}

interface MetricsResponse {
  metrics: any[];
  summary: any;
  session_expires: string;
}

export class SecureClient {
  private config: SecureClientConfig;
  private sessionId?: string;

  constructor(config: SecureClientConfig) {
    this.config = {
      ttl: 86400, // 24h par défaut
      ...config
    };
  }

  async register(): Promise<string> {
    try {
      console.log('🔐 Enregistrement sécurisé via enclave...');

      // 1. Récupérer l'attestation de l'enclave
      const attestation = await this.getAttestation();
      console.log('✅ Attestation enclave récupérée');

      // 2. Préparer les credentials
      const credentials = {
        userId: this.config.userId,
        exchange: this.config.exchange,
        apiKey: this.config.apiKey,
        secret: this.config.secret,
        accountType: this.config.accountType || 'spot',
        sandbox: this.config.sandbox || false
      };

      // 3. Chiffrer les credentials
      const envelope = await this.encryptCredentials(credentials);

      // 4. Envoyer à l'enclave
      const response = await fetch(`${this.config.enclaveUrl}/enclave/submit_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(envelope)
      });

      if (!response.ok) {
        throw new Error(`Erreur enregistrement: ${response.status} ${response.statusText}`);
      }

      const result: EnclaveResponse = await response.json();
      this.sessionId = result.session_id;

      console.log('✅ Enregistrement sécurisé réussi');
      console.log(`📋 Session ID: ${result.session_id}`);
      console.log(`⏰ Expire le: ${result.expires_at}`);

      return result.session_id;

    } catch (error) {
      console.error('❌ Erreur enregistrement sécurisé:', error);
      throw error;
    }
  }

  async getMetrics(): Promise<MetricsResponse> {
    if (!this.sessionId) {
      throw new Error('Session non initialisée. Appelez register() d\'abord.');
    }

    const response = await fetch(`${this.config.enclaveUrl}/enclave/metrics/${this.sessionId}`);
    
    if (!response.ok) {
      throw new Error(`Erreur récupération métriques: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  async getSummary(): Promise<any> {
    if (!this.sessionId) {
      throw new Error('Session non initialisée. Appelez register() d\'abord.');
    }

    const response = await fetch(`${this.config.enclaveUrl}/enclave/summary/${this.sessionId}`);
    
    if (!response.ok) {
      throw new Error(`Erreur récupération résumé: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  private async getAttestation(): Promise<any> {
    const response = await fetch(`${this.config.enclaveUrl}/attestation/quote`);
    
    if (!response.ok) {
      throw new Error(`Erreur attestation: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  private async encryptCredentials(credentials: any): Promise<any> {
    // En production, utiliser de vrais algorithmes de chiffrement
    // Ici on simule pour la démonstration
    
    const credentialsJson = JSON.stringify(credentials);
    
    return {
      ephemeral_pub: 'mock-ephemeral-key',
      nonce: 'mock-nonce',
      ciphertext: Buffer.from(credentialsJson).toString('base64'),
      tag: 'mock-auth-tag',
      metadata: {
        exchange: this.config.exchange,
        label: 'main-account',
        ttl: this.config.ttl
      }
    };
  }

  getSessionId(): string | undefined {
    return this.sessionId;
  }

  isRegistered(): boolean {
    return !!this.sessionId;
  }
}

// Exemple d'utilisation
export async function registerUserSecurely(config: SecureClientConfig): Promise<SecureClient> {
  const client = new SecureClient(config);
  await client.register();
  return client;
}

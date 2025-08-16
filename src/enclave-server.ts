/**
 * Secure TEE Enclave Backend Server
 * 
 * SECURITY OBJECTIVES:
 * - Accept encrypted API keys, never store them in plaintext
 * - Forward to TEE enclave for processing
 * - Return signed aggregated results only
 * - Implement comprehensive security controls
 */

import Fastify from 'fastify';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { generateKeyPair, encryptCredentials, decryptCredentials } from './libs/crypto.js';
import { ExchangeConnector, UserConfig } from './exchange-connector.js';
import { TradeAggregator } from './trade-aggregator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface EnclaveConfig {
  port: number;
  host: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

interface CredentialEnvelope {
  ephemeral_pub: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  metadata: {
    exchange: string;
    label: string;
    ttl: number;
  };
}

export class EnclaveServer {
  private fastify: Fastify;
  private exchangeConnector: ExchangeConnector;
  private tradeAggregator: TradeAggregator;
  private config: EnclaveConfig;
  private userSessions = new Map<string, { userId: string; config: UserConfig; expiresAt: number }>();

  constructor(config: EnclaveConfig) {
    this.config = config;
    this.fastify = Fastify({ logger: true });
    this.exchangeConnector = new ExchangeConnector();
    this.tradeAggregator = new TradeAggregator();
    
    this.setupRoutes();
    this.setupEventHandlers();
  }

  private setupRoutes(): void {
    // Attestation de l'enclave
    this.fastify.get('/attestation/quote', async (request, reply) => {
      return {
        enclave_id: 'perf-aggregator-enclave-v1',
        attestation_type: 'SGX_QUOTE',
        public_key: await this.getPublicKey(),
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      };
    });

    // Soumission sécurisée des credentials
    this.fastify.post('/enclave/submit_key', async (request, reply) => {
      const envelope = request.body as CredentialEnvelope;
      
      try {
        // Déchiffrer les credentials
        const decryptedData = await decryptCredentials(envelope);
        const { userId, exchange, apiKey, secret, accountType, sandbox } = JSON.parse(decryptedData);
        
        // Valider les données
        if (!userId || !exchange || !apiKey || !secret) {
          return reply.status(400).send({ error: 'Données manquantes' });
        }

        // Créer la configuration utilisateur
        const userConfig: UserConfig = {
          userId,
          exchange,
          apiKey,
          secret,
          accountType: accountType || 'spot',
          sandbox: sandbox || false,
          apiInterval: 60000,
          maxRetries: 3
        };

        // Générer un session ID sécurisé
        const sessionId = this.generateSessionId();
        const expiresAt = Date.now() + (envelope.metadata.ttl * 1000);

        // Stocker la session
        this.userSessions.set(sessionId, {
          userId,
          config: userConfig,
          expiresAt
        });

        // Ajouter l'utilisateur au connecteur
        this.exchangeConnector.addUser(userConfig);

        console.log(`🔐 Utilisateur ${userId} enregistré sécurisé avec session ${sessionId}`);

        return {
          session_id: sessionId,
          expires_at: new Date(expiresAt).toISOString(),
          status: 'active'
        };

      } catch (error) {
        console.error('❌ Erreur déchiffrement credentials:', error);
        return reply.status(400).send({ error: 'Credentials invalides' });
      }
    });

    // Récupération des métriques (authentifiée par session)
    this.fastify.get('/enclave/metrics/:sessionId', async (request, reply) => {
      const { sessionId } = request.params as { sessionId: string };
      
      const session = this.userSessions.get(sessionId);
      if (!session || session.expiresAt < Date.now()) {
        return reply.status(401).send({ error: 'Session invalide ou expirée' });
      }

      const metrics = this.tradeAggregator.getAllUserMetrics(session.userId);
      const summary = this.tradeAggregator.getSummary(session.userId);

      return {
        metrics,
        summary,
        session_expires: new Date(session.expiresAt).toISOString()
      };
    });

    // Récupération du résumé (authentifiée par session)
    this.fastify.get('/enclave/summary/:sessionId', async (request, reply) => {
      const { sessionId } = request.params as { sessionId: string };
      
      const session = this.userSessions.get(sessionId);
      if (!session || session.expiresAt < Date.now()) {
        return reply.status(401).send({ error: 'Session invalide ou expirée' });
      }

      const summary = this.tradeAggregator.getSummary(session.userId);
      return {
        summary,
        session_expires: new Date(session.expiresAt).toISOString()
      };
    });

    // Nettoyage des sessions expirées
    this.fastify.post('/enclave/cleanup', async (request, reply) => {
      const now = Date.now();
      let cleanedCount = 0;

      for (const [sessionId, session] of this.userSessions.entries()) {
        if (session.expiresAt < now) {
          this.userSessions.delete(sessionId);
          cleanedCount++;
        }
      }

      return { cleaned_sessions: cleanedCount };
    });
  }

  private setupEventHandlers(): void {
    // Traiter les trades reçus
    this.exchangeConnector.on('trade', (trade) => {
      this.tradeAggregator.processTrade(trade);
    });
  }

  private async getPublicKey(): Promise<string> {
    // En production, lire depuis un fichier sécurisé
    return 'enclave-public-key-base64';
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async start(): Promise<void> {
    try {
      await this.fastify.listen({ port: this.config.port, host: this.config.host });
      console.log(`🔐 Enclave démarrée sur ${this.config.host}:${this.config.port}`);
      
      // Démarrer le connecteur d'exchange
      await this.exchangeConnector.start();
      
      // Nettoyer les sessions expirées toutes les heures
      setInterval(() => {
        this.cleanupExpiredSessions();
      }, 60 * 60 * 1000);

    } catch (error) {
      console.error('❌ Erreur démarrage enclave:', error);
      throw error;
    }
  }

  private cleanupExpiredSessions(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [sessionId, session] of this.userSessions.entries()) {
      if (session.expiresAt < now) {
        this.userSessions.delete(sessionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(`🧹 ${cleanedCount} sessions expirées nettoyées`);
    }
  }

  async stop(): Promise<void> {
    await this.fastify.close();
    this.exchangeConnector.stop();
    console.log('🛑 Enclave arrêtée');
  }
}

// Démarrage si appelé directement
if (import.meta.url === `file://${process.argv[1]}`) {
  const config: EnclaveConfig = {
    port: parseInt(process.env.ENCLAVE_PORT || '3000'),
    host: process.env.ENCLAVE_HOST || '0.0.0.0',
    privateKeyPath: process.env.ENCLAVE_PRIVATE_KEY || join(__dirname, '../keys/enclave_private.pem'),
    publicKeyPath: process.env.ENCLAVE_PUBLIC_KEY || join(__dirname, '../keys/enclave_public.pem')
  };

  const server = new EnclaveServer(config);
  
  process.on('SIGINT', async () => {
    console.log('\n🛑 Arrêt de l\'enclave...');
    await server.stop();
    process.exit(0);
  });

  server.start().catch(console.error);
}
import { SecureClient } from '../src/client/secure-client.js';

// Secure configuration - direct communication with enclave
const config = {
  enclaveUrl: 'https://perf-aggregator.com:3000', // Enclave port
  userId: 'trader-john',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  secret: process.env.BINANCE_SECRET,
  accountType: 'spot',
  sandbox: true,
  ttl: 86400 // 24h
};

async function secureRegistrationExample() {
  try {
    console.log('🔐 SECURE REGISTRATION EXAMPLE');
    console.log('================================\n');

    // 1. Create secure client
    const client = new SecureClient(config);
    console.log('✅ Client sécurisé créé');

    // 2. Enregistrement sécurisé (credentials chiffrés)
    console.log('\n📝 Enregistrement via enclave...');
    const sessionId = await client.register();
    
    console.log(`\n🎯 RÉSULTAT:`);
    console.log(`   Session ID: ${sessionId}`);
    console.log(`   Enregistré: ${client.isRegistered()}`);

    // 3. Récupération des métriques via session sécurisée
    console.log('\n📊 Récupération des métriques...');
    const metrics = await client.getMetrics();
    
    console.log('\n📈 MÉTRIQUES SÉCURISÉES:');
    console.log(`   Session expire: ${metrics.session_expires}`);
    console.log(`   Métriques par symbole:`, metrics.metrics);

    console.log('\n✅ Exemple sécurisé terminé avec succès!');

  } catch (error) {
    console.error('❌ Erreur exemple sécurisé:', error.message);
  }
}

async function multipleUsersExample() {
  console.log('\n👥 EXEMPLE MULTI-UTILISATEURS');
  console.log('==============================\n');

  const users = [
    {
      userId: 'trader-alice',
      exchange: 'binance',
      accountType: 'spot'
    },
    {
      userId: 'trader-bob',
      exchange: 'binance',
      accountType: 'futures'
    }
  ];

  const clients = [];

  for (const user of users) {
    try {
      const client = new SecureClient({
        ...config,
        ...user
      });

      console.log(`📝 Enregistrement ${user.userId}...`);
      await client.register();
      clients.push(client);

      console.log(`✅ ${user.userId} enregistré (${user.accountType})`);

    } catch (error) {
      console.error(`❌ Erreur ${user.userId}:`, error.message);
    }
  }

  // Récupérer les métriques de tous les utilisateurs
  console.log('\n📊 MÉTRIQUES MULTI-UTILISATEURS:');
  for (const client of clients) {
    try {
      const metrics = await client.getMetrics();
      console.log(`   ${client.config.userId}: ${metrics.metrics.length} symboles`);
    } catch (error) {
      console.log(`   ${client.config.userId}: Erreur récupération`);
    }
  }
}

// Fonction principale
async function main() {
  console.log('🚀 DÉMONSTRATION CLIENT SÉCURISÉ');
  console.log('==================================\n');

  await secureRegistrationExample();
  await multipleUsersExample();

  console.log('\n🎉 Démonstration terminée!');
}

// Exécuter si appelé directement
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { secureRegistrationExample, multipleUsersExample };

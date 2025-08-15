import { ExchangeConnector } from '../src/exchange-connector.js';

// Configuration optimisée pour API REST avec polling adaptatif
const config = {
  userId: 'user-123',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  secret: process.env.BINANCE_SECRET,
  sandbox: true, // Utiliser le sandbox pour les tests
  accountType: 'spot', // spot, futures, ou margin
  apiInterval: 60000, // 1 minute entre les appels API (polling adaptatif)
  maxRetries: 3
};

// Initialiser le connecteur
const connector = new ExchangeConnector();

// Écouter les trades
connector.on('trade', (trade) => {
  console.log('📊 Trade reçu:', {
    userId: trade.userId,
    symbol: trade.symbol,
    side: trade.side,
    amount: trade.amount,
    price: trade.price,
    timestamp: new Date(trade.timestamp).toISOString()
  });
});

// Démarrer le service
async function startService() {
  try {
    // Ajouter l'utilisateur
    connector.addUser(config);
    
    // Démarrer le monitoring
    await connector.start();
    
    console.log('✅ Service démarré avec API REST adaptatif');
    console.log(`📡 Monitoring automatique de tous les symboles (${config.accountType})`);
    console.log('🔄 Intervalle adaptatif : 30s-5min selon l\'activité');
    
  } catch (error) {
    console.error('❌ Erreur démarrage:', error);
  }
}

// Gestion propre de l'arrêt
process.on('SIGINT', () => {
  console.log('\n🛑 Arrêt du service...');
  connector.stop();
  process.exit(0);
});

startService();

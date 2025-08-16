import { ExchangeConnector } from '../src/exchange-connector.js';

// Optimized configuration for REST API with adaptive polling
const config = {
  userId: 'user-123',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  secret: process.env.BINANCE_SECRET,
  sandbox: true, // Use sandbox for testing
  accountType: 'spot', // spot, futures, or margin
  apiInterval: 60000, // 1 minute between API calls (adaptive polling)
  maxRetries: 3
};

// Initialize connector
const connector = new ExchangeConnector();

// Listen for trades
connector.on('trade', (trade) => {
  console.log('📊 Trade received:', {
    userId: trade.userId,
    symbol: trade.symbol,
    side: trade.side,
    amount: trade.amount,
    price: trade.price,
    timestamp: new Date(trade.timestamp).toISOString()
  });
});

// Start service
async function startService() {
  try {
    // Add user
    connector.addUser(config);
    
    // Start monitoring
    await connector.start();
    
    console.log('✅ Service started with adaptive REST API');
    console.log(`📡 Automatic monitoring of all symbols (${config.accountType})`);
    console.log('🔄 Adaptive interval: 30s-5min based on activity');
    
  } catch (error) {
    console.error('❌ Startup error:', error);
  }
}

// Clean shutdown handling
process.on('SIGINT', () => {
  console.log('\n🛑 Stopping service...');
  connector.stop();
  process.exit(0);
});

startService();

import ccxt from 'ccxt';
import { EventEmitter } from 'events';

export interface UserTrade {
  userId: string;
  symbol: string;
  side: 'buy' | 'sell';
  amount: number;
  price: number;
  fee: number;
  timestamp: number;
  exchange: string;
}

export interface UserConfig {
  userId: string;
  exchange: string;
  apiKey: string;
  secret: string;
  sandbox?: boolean;
  symbols?: string[];
}

export class ExchangeConnector extends EventEmitter {
  private exchanges = new Map<string, any>();
  private userConfigs = new Map<string, UserConfig>();
  private isRunning = false;

  constructor() {
    super();
  }

  addUser(config: UserConfig): void {
    console.log(`➕ Ajout utilisateur ${config.userId} sur ${config.exchange}`);
    
    try {
      // Créer l'instance CCXT
      const ExchangeClass = ccxt[config.exchange as keyof typeof ccxt] as any;
      if (!ExchangeClass) {
        throw new Error(`Exchange ${config.exchange} non supporté`);
      }

      const exchange = new ExchangeClass({
        apiKey: config.apiKey,
        secret: config.secret,
        sandbox: config.sandbox || false,
        enableRateLimit: true,
      });

      const exchangeKey = `${config.userId}_${config.exchange}`;
      this.exchanges.set(exchangeKey, exchange);
      this.userConfigs.set(config.userId, config);
      
    } catch (error) {
      console.error(`❌ Erreur ajout utilisateur ${config.userId}:`, error);
      throw error;
    }
  }

  removeUser(userId: string): void {
    console.log(`➖ Suppression utilisateur ${userId}`);
    const config = this.userConfigs.get(userId);
    if (config) {
      const exchangeKey = `${userId}_${config.exchange}`;
      this.exchanges.delete(exchangeKey);
      this.userConfigs.delete(userId);
    }
  }

  async start(): Promise<void> {
    if (this.isRunning) return;
    
    console.log('🚀 Démarrage du connecteur d\'exchanges...');
    this.isRunning = true;

    // Démarrer la surveillance des trades pour chaque utilisateur
    for (const [userId, config] of this.userConfigs) {
      this.startUserTradeMonitoring(userId, config);
    }
  }

  stop(): void {
    console.log('🛑 Arrêt du connecteur d\'exchanges...');
    this.isRunning = false;
    
    // Fermer toutes les connexions
    for (const exchange of this.exchanges.values()) {
      if (exchange.close) {
        exchange.close();
      }
    }
  }

  private async startUserTradeMonitoring(userId: string, config: UserConfig): Promise<void> {
    const exchangeKey = `${userId}_${config.exchange}`;
    const exchange = this.exchanges.get(exchangeKey);
    
    if (!exchange) {
      console.error(`❌ Exchange non trouvé pour ${userId}`);
      return;
    }

    try {
      // Polling des trades récents (toutes les 30s)
      const pollTrades = async () => {
        if (!this.isRunning) return;
        
        try {
          const symbols = config.symbols || ['BTC/USDT', 'ETH/USDT'];
          
          for (const symbol of symbols) {
            const trades = await exchange.fetchMyTrades(symbol, undefined, 50);
            
            for (const trade of trades) {
              const userTrade: UserTrade = {
                userId,
                symbol: trade.symbol,
                side: trade.side as 'buy' | 'sell',
                amount: trade.amount,
                price: trade.price,
                fee: trade.fee?.cost || 0,
                timestamp: trade.timestamp || Date.now(),
                exchange: config.exchange
              };
              
              // Émettre le trade pour traitement
              this.emit('trade', userTrade);
            }
          }
        } catch (error) {
          console.error(`❌ Erreur récupération trades ${userId}:`, error);
        }
        
        // Reprogrammer le polling
        if (this.isRunning) {
          setTimeout(pollTrades, 30000); // 30 secondes
        }
      };

      // Démarrer le polling
      setTimeout(pollTrades, 1000);
      
    } catch (error) {
      console.error(`❌ Erreur démarrage monitoring ${userId}:`, error);
    }
  }
}

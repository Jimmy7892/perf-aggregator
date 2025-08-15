import { EventEmitter } from 'events';
import ccxt from 'ccxt';

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
  accountType?: 'spot' | 'futures' | 'margin'; // Type de compte à surveiller
  apiInterval?: number; // Intervalle en ms pour les appels API
  maxRetries?: number;
}

export class ExchangeConnector extends EventEmitter {
  private exchanges = new Map<string, any>();
  private userConfigs = new Map<string, UserConfig>();
  private pollingIntervals = new Map<string, NodeJS.Timeout>();
  private isRunning = false;
  private lastTradeTimestamps = new Map<string, number>();

  constructor() {
    super();
  }

  addUser(config: UserConfig): void {
    console.log(`➕ Ajout utilisateur ${config.userId} sur ${config.exchange}`);
    
    try {
      const exchangeClass = ccxt[config.exchange as keyof typeof ccxt] as any;
      if (!exchangeClass) {
        throw new Error(`Exchange ${config.exchange} non supporté`);
      }

      const exchange = new exchangeClass({
        apiKey: config.apiKey,
        secret: config.secret,
        sandbox: config.sandbox || false,
        enableRateLimit: true,
        rateLimit: 1000, // 1 seconde entre les requêtes
      });

      const exchangeKey = `${config.userId}_${config.exchange}`;
      this.exchanges.set(exchangeKey, exchange);
      this.userConfigs.set(config.userId, config);
      this.lastTradeTimestamps.set(exchangeKey, Date.now() - 60000); // 1 minute en arrière
      
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
      
      // Arrêter le polling
      const interval = this.pollingIntervals.get(exchangeKey);
      if (interval) {
        clearInterval(interval);
        this.pollingIntervals.delete(exchangeKey);
      }
      
      this.exchanges.delete(exchangeKey);
      this.userConfigs.delete(userId);
      this.lastTradeTimestamps.delete(exchangeKey);
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
    
    // Arrêter tous les polling
    for (const interval of this.pollingIntervals.values()) {
      clearInterval(interval);
    }
    this.pollingIntervals.clear();
    
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

    // Polling adaptatif : plus fréquent si activité, moins fréquent si inactif
    const baseInterval = config.apiInterval || 60000; // 1 minute par défaut
    const maxRetries = config.maxRetries || 3;
    let currentInterval = baseInterval;
    let consecutiveEmptyResponses = 0;

    console.log(`📡 Démarrage monitoring API REST adaptatif pour ${userId} (${baseInterval}ms)`);

    const pollTrades = async (retryCount = 0): Promise<void> => {
      if (!this.isRunning) return;
      
      try {
        const lastTimestamp = this.lastTradeTimestamps.get(exchangeKey) || Date.now() - 60000;
        
        // Récupérer TOUS les trades récents sans spécifier de symbole
        const trades = await exchange.fetchMyTrades(undefined, lastTimestamp, 100);
        
        if (trades.length > 0) {
          console.log(`📊 ${trades.length} nouveaux trades pour ${userId} (tous symboles)`);
          
          // Réduire l'intervalle si activité détectée
          if (consecutiveEmptyResponses > 0) {
            currentInterval = Math.max(baseInterval / 2, 30000); // Min 30s
            consecutiveEmptyResponses = 0;
            console.log(`⚡ Activité détectée, intervalle réduit à ${currentInterval}ms`);
          }
          
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
            
            // Mettre à jour le timestamp du dernier trade
            if (trade.timestamp > lastTimestamp) {
              this.lastTradeTimestamps.set(exchangeKey, trade.timestamp);
            }
          }
        } else {
          consecutiveEmptyResponses++;
          
          // Augmenter l'intervalle si pas d'activité
          if (consecutiveEmptyResponses >= 5) {
            currentInterval = Math.min(baseInterval * 2, 300000); // Max 5min
            console.log(`😴 Pas d'activité, intervalle augmenté à ${currentInterval}ms`);
          }
        }
        
        // Reset retry count on success
        retryCount = 0;
        
      } catch (error) {
        console.error(`❌ Erreur récupération trades ${userId}:`, error);
        
        // Retry logic avec backoff exponentiel
        if (retryCount < maxRetries) {
          const backoffDelay = Math.min(baseInterval * Math.pow(2, retryCount), 300000); // Max 5 minutes
          console.log(`🔄 Retry ${retryCount + 1}/${maxRetries} dans ${backoffDelay}ms pour ${userId}`);
          
          setTimeout(() => pollTrades(retryCount + 1), backoffDelay);
        } else {
          console.error(`❌ Échec définitif après ${maxRetries} tentatives pour ${userId}`);
        }
      }
    };

    // Démarrer le polling adaptatif
    const startPolling = () => {
      pollTrades().then(() => {
        if (this.isRunning) {
          setTimeout(startPolling, currentInterval);
        }
      });
    };
    
    // Premier appel immédiat
    setTimeout(startPolling, 1000);
  }
}

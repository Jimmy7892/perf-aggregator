import { UserTrade } from './exchange-connector.js';

export interface TradeMetrics {
  userId: string;
  symbol: string;
  periodStart: string;
  periodEnd: string;
  
  // Métriques demandées
  volume: number;           // Volume total en USD
  trades: number;           // Nombre de trades
  returnPct: number;        // Return % basé sur trades individuels
  returnUsd: number;        // Return $ basé sur trades individuels
  
  // Détails pour calculs
  totalFees: number;        // Frais totaux
  realizedPnL: number;      // P&L réalisé
  totalTrades: number;      // Nombre total de trades
}

export interface TradePair {
  buyTrade: UserTrade;
  sellTrade: UserTrade;
  returnPct: number;
  returnUsd: number;
  fees: number;
}

export class TradeAggregator {
  private userTrades = new Map<string, UserTrade[]>(); // userId_symbol -> trades[]
  private tradePairs = new Map<string, TradePair[]>(); // userId_symbol -> trade pairs
  private metrics = new Map<string, TradeMetrics>();   // userId_symbol -> metrics
  
  constructor() {}

  processTrade(trade: UserTrade): void {
    const key = `${trade.userId}_${trade.symbol}`;
    
    // 1. Ajouter le trade à la liste
    if (!this.userTrades.has(key)) {
      this.userTrades.set(key, []);
    }
    this.userTrades.get(key)!.push(trade);
    
    // 2. Essayer de former des paires buy/sell
    this.formTradePairs(key);
    
    // 3. Recalculer les métriques
    this.calculateMetrics(key);
  }

  private formTradePairs(key: string): void {
    const trades = this.userTrades.get(key) || [];
    const pairs: TradePair[] = [];
    
    // Trier les trades par timestamp
    trades.sort((a, b) => a.timestamp - b.timestamp);
    
    let buyTrades: UserTrade[] = [];
    let sellTrades: UserTrade[] = [];
    
    // Séparer les trades buy et sell
    for (const trade of trades) {
      if (trade.side === 'buy') {
        buyTrades.push(trade);
      } else {
        sellTrades.push(trade);
      }
    }
    
    // Former des paires buy/sell (FIFO)
    let buyIndex = 0;
    let sellIndex = 0;
    
    while (buyIndex < buyTrades.length && sellIndex < sellTrades.length) {
      const buyTrade = buyTrades[buyIndex];
      const sellTrade = sellTrades[sellIndex];
      
      // Vérifier que le sell trade vient après le buy trade
      if (sellTrade.timestamp > buyTrade.timestamp) {
        const buyAmount = buyTrade.amount;
        const sellAmount = sellTrade.amount;
        const matchedAmount = Math.min(buyAmount, sellAmount);
        
        // Calculer le return pour cette paire
        const buyValue = matchedAmount * buyTrade.price;
        const sellValue = matchedAmount * sellTrade.price;
        const totalFees = (buyTrade.fee * matchedAmount / buyTrade.amount) + 
                         (sellTrade.fee * matchedAmount / sellTrade.amount);
        
        const returnUsd = sellValue - buyValue - totalFees;
        const returnPct = (returnUsd / buyValue) * 100;
        
        pairs.push({
          buyTrade,
          sellTrade,
          returnPct,
          returnUsd,
          fees: totalFees
        });
        
        // Réduire les montants restants
        buyTrade.amount -= matchedAmount;
        sellTrade.amount -= matchedAmount;
        
        // Passer au trade suivant si épuisé
        if (buyTrade.amount <= 0) buyIndex++;
        if (sellTrade.amount <= 0) sellIndex++;
      } else {
        // Le sell trade est avant le buy trade, passer au sell suivant
        sellIndex++;
      }
    }
    
    this.tradePairs.set(key, pairs);
  }

  private calculateMetrics(key: string): void {
    const trades = this.userTrades.get(key) || [];
    const pairs = this.tradePairs.get(key) || [];
    
    if (trades.length === 0) return;
    
    // Calculer les métriques de base
    const volume = trades.reduce((sum, trade) => sum + (trade.amount * trade.price), 0);
    const totalFees = trades.reduce((sum, trade) => sum + trade.fee, 0);
    const realizedPnL = pairs.reduce((sum, pair) => sum + pair.returnUsd, 0);
    
    // Calculer le return % global
    const totalBuyValue = pairs.reduce((sum, pair) => {
      const matchedAmount = Math.min(pair.buyTrade.amount, pair.sellTrade.amount);
      return sum + (matchedAmount * pair.buyTrade.price);
    }, 0);
    
    const returnPct = totalBuyValue > 0 ? (realizedPnL / totalBuyValue) * 100 : 0;
    
    // Créer les métriques
    const metrics: TradeMetrics = {
      userId: trades[0].userId,
      symbol: trades[0].symbol,
      periodStart: new Date(Math.min(...trades.map(t => t.timestamp))).toISOString(),
      periodEnd: new Date(Math.max(...trades.map(t => t.timestamp))).toISOString(),
      volume,
      trades: trades.length,
      returnPct,
      returnUsd: realizedPnL,
      totalFees,
      realizedPnL,
      totalTrades: trades.length
    };
    
    this.metrics.set(key, metrics);
  }

  getMetrics(userId: string, symbol: string): TradeMetrics | undefined {
    return this.metrics.get(`${userId}_${symbol}`);
  }

  getAllUserMetrics(userId: string): TradeMetrics[] {
    const result: TradeMetrics[] = [];
    for (const [key, metrics] of this.metrics) {
      if (metrics.userId === userId) {
        result.push(metrics);
      }
    }
    return result;
  }

  getTradePairs(userId: string, symbol: string): TradePair[] {
    return this.tradePairs.get(`${userId}_${symbol}`) || [];
  }

  // Nettoyer les données anciennes (> 30 jours)
  cleanupOldData(): void {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000; // 30 jours
    
    for (const [key, trades] of this.userTrades) {
      const recentTrades = trades.filter(trade => trade.timestamp >= cutoff);
      if (recentTrades.length === 0) {
        this.userTrades.delete(key);
        this.tradePairs.delete(key);
        this.metrics.delete(key);
      } else {
        this.userTrades.set(key, recentTrades);
        // Recalculer les paires et métriques
        this.formTradePairs(key);
        this.calculateMetrics(key);
      }
    }
    
    console.log(`🧹 Nettoyage des données anciennes terminé`);
  }

  // Obtenir un résumé pour l'API
  getSummary(userId: string): {
    totalVolume: number;
    totalTrades: number;
    totalReturnPct: number;
    totalReturnUsd: number;
    totalFees: number;
    symbols: string[];
  } {
    const userMetrics = this.getAllUserMetrics(userId);
    
    const totalVolume = userMetrics.reduce((sum, m) => sum + m.volume, 0);
    const totalTrades = userMetrics.reduce((sum, m) => sum + m.trades, 0);
    const totalFees = userMetrics.reduce((sum, m) => sum + m.totalFees, 0);
    const totalReturnUsd = userMetrics.reduce((sum, m) => sum + m.returnUsd, 0);
    
    // Return % pondéré par volume
    const totalReturnPct = totalVolume > 0 ? (totalReturnUsd / totalVolume) * 100 : 0;
    
    const symbols = [...new Set(userMetrics.map(m => m.symbol))];
    
    return {
      totalVolume,
      totalTrades,
      totalReturnPct,
      totalReturnUsd,
      totalFees,
      symbols
    };
  }
}


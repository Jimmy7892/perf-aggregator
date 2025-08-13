import { UserTrade } from './exchange-connector.js';

export interface UserPosition {
  userId: string;
  symbol: string;
  totalBought: number;
  totalSold: number;
  totalVolume: number;
  totalFees: number;
  avgBuyPrice: number;
  avgSellPrice: number;
  lastUpdateTime: number;
}

export interface MinuteAggregation {
  userId: string;
  symbol: string;
  timestamp: string; // ISO minute (YYYY-MM-DDTHH:mm:00.000Z)
  returnPct: number;
  volume: number;
  fees: number;
  tradesCount: number;
}

export class TradeAggregator {
  private userPositions = new Map<string, UserPosition>();
  private minuteAggregations = new Map<string, MinuteAggregation>();
  
  constructor() {}

  processTrade(trade: UserTrade): void {
    // 1. Mettre à jour la position de l'utilisateur
    this.updateUserPosition(trade);
    
    // 2. Calculer l'agrégation par minute
    this.updateMinuteAggregation(trade);
  }

  private updateUserPosition(trade: UserTrade): void {
    const positionKey = `${trade.userId}_${trade.symbol}`;
    let position = this.userPositions.get(positionKey);
    
    if (!position) {
      position = {
        userId: trade.userId,
        symbol: trade.symbol,
        totalBought: 0,
        totalSold: 0,
        totalVolume: 0,
        totalFees: 0,
        avgBuyPrice: 0,
        avgSellPrice: 0,
        lastUpdateTime: trade.timestamp
      };
    }

    const tradeValue = trade.amount * trade.price;
    
    if (trade.side === 'buy') {
      const newTotalBought = position.totalBought + trade.amount;
      position.avgBuyPrice = (position.avgBuyPrice * position.totalBought + tradeValue) / newTotalBought;
      position.totalBought = newTotalBought;
    } else {
      const newTotalSold = position.totalSold + trade.amount;
      position.avgSellPrice = (position.avgSellPrice * position.totalSold + tradeValue) / newTotalSold;
      position.totalSold = newTotalSold;
    }

    position.totalVolume += tradeValue;
    position.totalFees += trade.fee;
    position.lastUpdateTime = trade.timestamp;

    this.userPositions.set(positionKey, position);
  }

  private updateMinuteAggregation(trade: UserTrade): void {
    // Arrondir à la minute
    const minuteTimestamp = new Date(trade.timestamp);
    minuteTimestamp.setSeconds(0, 0);
    const minuteKey = `${trade.userId}_${trade.symbol}_${minuteTimestamp.toISOString()}`;
    
    let aggregation = this.minuteAggregations.get(minuteKey);
    
    if (!aggregation) {
      aggregation = {
        userId: trade.userId,
        symbol: trade.symbol,
        timestamp: minuteTimestamp.toISOString(),
        returnPct: 0,
        volume: 0,
        fees: 0,
        tradesCount: 0
      };
    }

    aggregation.volume += trade.amount * trade.price;
    aggregation.fees += trade.fee;
    aggregation.tradesCount++;

    // Calculer le return basé sur la position actuelle
    const positionKey = `${trade.userId}_${trade.symbol}`;
    const position = this.userPositions.get(positionKey);
    
    if (position && position.totalBought > 0 && position.totalSold > 0) {
      // Return = (prix de vente moyen - prix d'achat moyen) / prix d'achat moyen
      // Ajusté pour les frais
      const netBuyPrice = position.avgBuyPrice + (position.totalFees / position.totalBought);
      const netSellPrice = position.avgSellPrice - (position.totalFees / position.totalSold);
      aggregation.returnPct = ((netSellPrice - netBuyPrice) / netBuyPrice) * 100;
    }

    this.minuteAggregations.set(minuteKey, aggregation);
  }

  getMinuteAggregations(fromTime?: Date): MinuteAggregation[] {
    const result: MinuteAggregation[] = [];
    const cutoff = fromTime ? fromTime.getTime() : Date.now() - 60000; // Dernière minute par défaut
    
    for (const aggregation of this.minuteAggregations.values()) {
      if (new Date(aggregation.timestamp).getTime() >= cutoff) {
        result.push(aggregation);
      }
    }
    
    return result.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }

  getUserPosition(userId: string, symbol: string): UserPosition | undefined {
    return this.userPositions.get(`${userId}_${symbol}`);
  }

  getAllUserPositions(userId: string): UserPosition[] {
    const result: UserPosition[] = [];
    for (const position of this.userPositions.values()) {
      if (position.userId === userId) {
        result.push(position);
      }
    }
    return result;
  }

  // Nettoyer les agrégations anciennes (> 24h)
  cleanupOldAggregations(): void {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000; // 24h
    const toDelete: string[] = [];
    
    for (const [key, aggregation] of this.minuteAggregations) {
      if (new Date(aggregation.timestamp).getTime() < cutoff) {
        toDelete.push(key);
      }
    }
    
    for (const key of toDelete) {
      this.minuteAggregations.delete(key);
    }
    
    console.log(`🧹 Nettoyé ${toDelete.length} agrégations anciennes`);
  }
}


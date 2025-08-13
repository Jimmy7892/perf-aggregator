// Connecteur en temps réel au mock exchange
import WebSocket from 'ws';
import axios from 'axios';

export interface LiveTradeData {
  symbol: string;
  price: number;
  size: number;
  side: 'buy' | 'sell';
  timestamp: number;
  fee: number;
}

export class LiveConnector {
  private ws: WebSocket | null = null;
  private trades: LiveTradeData[] = [];
  private aggregationInterval: NodeJS.Timeout | null = null;
  private isRunning = false;
  
  constructor(
    private mockExchangeWs: string,
    private aggregationIntervalMs: number = 60000 // 1 minute par défaut
  ) {}

  async start(): Promise<void> {
    if (this.isRunning) return;
    
    console.log('🚀 Démarrage du connecteur live au mock exchange...');
    this.isRunning = true;
    
    await this.connectToMockExchange();
    this.scheduleAggregations();
  }

  stop(): void {
    console.log('🛑 Arrêt du connecteur live...');
    this.isRunning = false;
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    
    if (this.aggregationInterval) {
      clearInterval(this.aggregationInterval);
      this.aggregationInterval = null;
    }
  }

  private async connectToMockExchange(): Promise<void> {
    return new Promise((resolve, reject) => {
      console.log(`🔌 Connexion au mock exchange: ${this.mockExchangeWs}`);
      
      this.ws = new WebSocket(this.mockExchangeWs);
      
      this.ws.on('open', () => {
        console.log('✅ Connecté au mock exchange via WebSocket');
        resolve();
      });
      
      this.ws.on('error', (error) => {
        console.error('❌ Erreur WebSocket:', error);
        reject(error);
      });
      
      this.ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          
          if (message.type === 'trade') {
            this.handleTrade(message.data);
          } else if (message.type === 'connected') {
            console.log('📡 Mock exchange connecté:', message.message);
          }
        } catch (error) {
          console.error('❌ Erreur parsing message WebSocket:', error);
        }
      });
      
      this.ws.on('close', () => {
        console.log('❌ Connexion WebSocket fermée');
        if (this.isRunning) {
          // Reconnexion automatique après 5 secondes
          setTimeout(() => {
            if (this.isRunning) {
              console.log('🔄 Tentative de reconnexion...');
              this.connectToMockExchange().catch(console.error);
            }
          }, 5000);
        }
      });
    });
  }

  private handleTrade(trade: any): void {
    const liveTradeData: LiveTradeData = {
      symbol: trade.symbol,
      price: trade.price,
      size: trade.size,
      side: trade.side,
      timestamp: trade.timestamp,
      fee: trade.fee
    };
    
    this.trades.push(liveTradeData);
    
    // Garder seulement les 1000 derniers trades
    if (this.trades.length > 1000) {
      this.trades = this.trades.slice(-500);
    }
    
    console.log(`💰 Trade reçu: ${trade.symbol} ${trade.side} ${trade.size} @ ${trade.price} (fee: ${trade.fee})`);
  }

  private scheduleAggregations(): void {
    const intervalMinutes = this.aggregationIntervalMs / 60000;
    console.log(`⏰ Programmation des agrégations toutes les ${intervalMinutes} minute(s)...`);
    
    // Première agrégation après l'intervalle
    setTimeout(() => {
      this.performAggregation();
    }, this.aggregationIntervalMs);
    
    // Puis toutes les N minutes
    this.aggregationInterval = setInterval(() => {
      this.performAggregation();
    }, this.aggregationIntervalMs);
  }

  private performAggregation(): void {
    if (this.trades.length === 0) {
      console.log('⚠️  Pas de trades à agréger');
      return;
    }

    console.log(`\n📊 === AGRÉGATION AUTONOME ${new Date().toISOString()} ===`);
    console.log(`📈 Nombre de trades collectés: ${this.trades.length}`);
    
    // Statistiques globales
    const symbols = [...new Set(this.trades.map(t => t.symbol))];
    const totalVolume = this.trades.reduce((sum, t) => sum + (t.price * t.size), 0);
    const totalFees = this.trades.reduce((sum, t) => sum + t.fee, 0);
    
    console.log(`💎 Symboles traités: ${symbols.join(', ')}`);
    console.log(`💰 Volume total: $${totalVolume.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`);
    console.log(`💸 Fees totales: $${totalFees.toFixed(2)}`);
    
    // Agrégation par symbole et par heure
    const hourlyData = this.aggregateBySymbolAndHour();
    
    for (const [hourKey, symbols] of Object.entries(hourlyData)) {
      console.log(`\n⏰ Heure UTC: ${hourKey}`);
      
      for (const [symbol, data] of Object.entries(symbols)) {
        console.log(`   📋 ${symbol}:`);
        console.log(`      🔢 Trades: ${data.count}`);
        console.log(`      💵 Prix: $${data.startPrice} → $${data.endPrice} (${data.priceChange >= 0 ? '+' : ''}${data.priceChange.toFixed(2)}%)`);
        console.log(`      📏 Volume: ${data.volumeBase.toFixed(4)} ${symbol.slice(0, -4)} ($${data.volumeUSD.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })})`);
        console.log(`      ⚡ Fees: $${data.fees.toFixed(2)}`);
      }
    }
    
    console.log(`📊 === FIN AGRÉGATION AUTONOME ===\n`);
  }

  private aggregateBySymbolAndHour(): Record<string, Record<string, any>> {
    const hourlyData: Record<string, Record<string, any>> = {};
    
    for (const trade of this.trades) {
      const hourKey = new Date(trade.timestamp).toISOString().slice(0, 13) + ':00:00.000Z';
      
      if (!hourlyData[hourKey]) {
        hourlyData[hourKey] = {};
      }
      
      if (!hourlyData[hourKey][trade.symbol]) {
        hourlyData[hourKey][trade.symbol] = {
          count: 0,
          volumeBase: 0,
          volumeUSD: 0,
          fees: 0,
          startPrice: trade.price,
          endPrice: trade.price,
          priceChange: 0,
          firstTimestamp: trade.timestamp,
          lastTimestamp: trade.timestamp
        };
      }
      
      const data = hourlyData[hourKey][trade.symbol];
      data.count++;
      data.volumeBase += trade.size;
      data.volumeUSD += trade.price * trade.size;
      data.fees += trade.fee;
      
      // Mise à jour des prix selon l'ordre temporel
      if (trade.timestamp < data.firstTimestamp) {
        data.firstTimestamp = trade.timestamp;
        data.startPrice = trade.price;
      }
      if (trade.timestamp > data.lastTimestamp) {
        data.lastTimestamp = trade.timestamp;
        data.endPrice = trade.price;
      }
      
      // Calcul du changement de prix
      data.priceChange = data.startPrice > 0 ? ((data.endPrice - data.startPrice) / data.startPrice) * 100 : 0;
    }
    
    return hourlyData;
  }

  getTradesCount(): number {
    return this.trades.length;
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
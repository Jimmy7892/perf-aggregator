# Perf-Aggregator - Performance Trading Aggregation Service

Professional real-time trading performance aggregation service: secure collection of trading data via optimized REST API, in-memory aggregation, ED25519 cryptographic signature, and generation of performance metrics compliant with financial standards.

## Architecture

### **Secure Architecture - Direct Enclave Communication**
```
Client → Secure Enclave (direct)
       ↑
     Encrypted credentials only
```

### **Components**
- **Performance Aggregator Server** : Port 3000 - Complete service in secure environment
- **ExchangeConnector** : Trading data collection from exchanges (adaptive polling)
- **TradeAggregator** : Real-time performance metrics calculation
- **Secure Client** : End-to-end encrypted communication
- **ED25519 Signature** : Cryptographic integrity of aggregations
- **Auto-detection** : All financial instruments automatically detected

### **Security Benefits**
- **Zero exposure** of credentials to your infrastructure
- **End-to-end encryption** of sensitive data
- **Temporary sessions** with automatic expiration
- **Cryptographic attestation** of enclave

## Configuration

### Environment Variables
- AGGREGATOR_PORT (default: 5000)
- AGGREGATOR_WS_PORT (default: 5010)
- AGGREGATOR_BACKEND_URL (ingestion API URL; ex: http://localhost:3010)
- AGGREGATOR_PRIVATE_KEY (path to ED25519 private key mounted as volume)

### Exchange Configuration
- `apiInterval` : Interval between API calls (default: 60000ms)
- `maxRetries` : Number of retry attempts on failure (default: 3)
- `accountType` : Account type to monitor ('spot', 'futures', 'margin')
- `sandbox` : Use test environment
- **Auto-detection** : All financial instruments are automatically detected

## Deployment

### **For Users (Clients) - RECOMMENDED**

#### **Secure Registration (Recommended)**
Direct communication with enclave - **ZERO exposure** of credentials:

```powershell
# PowerShell - Direct communication with enclave
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -ServiceUrl "https://perf-aggregator.com" -Secure

# JavaScript - Secure client
node examples/secure-client-example.js
```

#### **Simple Registration (Not Recommended)**
Via main server - credentials exposed:

```powershell
# PowerShell - Via main server (less secure)
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -ServiceUrl "https://perf-aggregator.com"
```

### **For Developers (Server)**
```bash
pnpm i
pnpm build
pnpm start
```

**Single unified server** - no separate enclave service needed.

## Docker

`ash
docker build -t perf-aggregator:latest .
docker run -p 3000:3000 \
  -e ENCLAVE_PORT=3000 \
  -e ENCLAVE_HOST=0.0.0.0 \
  perf-aggregator:latest
`

## Service API

### Secure Enclave Endpoints:
- GET `/attestation/quote` - Get enclave attestation
- POST `/enclave/submit_key` - Submit encrypted credentials
- GET `/enclave/metrics/:sessionId` - Get performance metrics
- GET `/enclave/summary/:sessionId` - Get summary metrics
- POST `/enclave/cleanup` - Cleanup expired sessions

Trade format:
`json
{  type: trade, data: { symbol: BTCUSDT, price: 50000, size: 0.1, side: buy, timestamp: 1640995200000, fee: 1.5 } }
`

## Ingestion Contract (target backend)

- Method: POST {AGGREGATOR_BACKEND_URL}/api/ingest
- ContentType: application/json
- Body: ED25519 signed object, for example:

`json
{
  client_id: test-client-1,
  exchange: mock,
  connector_version: 0.2.0,
  period_start: 2025-01-01T00:00:00.000Z,
  period_end: 2025-01-01T00:00:00.000Z,
  hourly_buckets: [
    { t: 2025-01-01T00:00:00.000Z, return_pct: 1.23, trades: 10, volume_base: 1.0, volume_quote: 50000, fees_usd: 1.5 }
  ],
  totals: { trades: 10, volume_base: 1.0, volume_quote: 50000, fees_usd: 1.5 },
  signature: base64
}
`

Toute API respectant ce contrat peut être utilisée (backend maison, serverless, etc.).

## Sécurité

- La clé privée ED25519 nest jamais committée; monter le fichier en lecture seule au runtime.
- Aucune rétention de trades bruts; seules des agrégations sont transmises.


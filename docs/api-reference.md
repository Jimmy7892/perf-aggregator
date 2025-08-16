# Performance Aggregator API Reference

**Version**: 1.0.0  
**Base URL**: `https://perf-aggregator.company.com`  
**Security**: TEE Enclave with X25519+AES-GCM encryption  
**Authentication**: Session-based with cryptographic attestation  

## Overview

The Performance Aggregator API provides institutional-grade secure access to trading performance analytics through a Trusted Execution Environment (TEE). All sensitive operations are performed within the secure enclave, ensuring zero-exposure of trading credentials.

### Security Model
- **Credential Protection**: API keys never exist in plaintext outside the secure enclave
- **End-to-End Encryption**: X25519 ECDH + AES-256-GCM for all sensitive data
- **Session Management**: Time-limited secure sessions with automatic expiration
- **Cryptographic Attestation**: Hardware-backed proof of enclave integrity

## Authentication Flow

### 1. Enclave Attestation

Clients must first verify the enclave's authenticity before submitting credentials.

#### Get Enclave Attestation Quote

```http
GET /attestation/quote
```

**Response**:
```json
{
  "enclave_id": "perf-aggregator-enclave-v1",
  "attestation_type": "SGX_QUOTE",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "measurement": "a1b2c3d4e5f6...",
  "signature": "base64-encoded-signature"
}
```

**Response Fields**:
- `enclave_id`: Unique identifier for the enclave instance
- `attestation_type`: Type of attestation (SGX_QUOTE, DCAP, etc.)
- `public_key`: Enclave's public key for credential encryption
- `timestamp`: Attestation generation timestamp
- `version`: Enclave software version
- `measurement`: Hash of enclave code and configuration
- `signature`: Cryptographic signature of attestation

### 2. Secure Credential Submission

Submit encrypted trading credentials to establish a secure session.

#### Submit Encrypted Credentials

```http
POST /enclave/submit_key
Content-Type: application/json
```

**Request Body**:
```json
{
  "ephemeral_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "nonce": "base64-encoded-nonce",
  "ciphertext": "base64-encoded-encrypted-credentials",
  "tag": "base64-encoded-auth-tag",
  "metadata": {
    "exchange": "binance",
    "label": "institutional-trading-bot-1",
    "ttl": 86400
  }
}
```

**Request Fields**:
- `ephemeral_pub`: Client's ephemeral X25519 public key (PEM format)
- `nonce`: 96-bit random nonce for AES-GCM (base64)
- `ciphertext`: Encrypted credentials payload (base64)
- `tag`: 128-bit authentication tag for AES-GCM (base64)
- `metadata.exchange`: Target exchange identifier
- `metadata.label`: Human-readable session label
- `metadata.ttl`: Session time-to-live in seconds (max: 604800)

**Encrypted Credentials Payload** (before encryption):
```json
{
  "userId": "institutional-trader-001",
  "exchange": "binance",
  "apiKey": "institutional-api-key",
  "apiSecret": "institutional-api-secret",
  "accountType": "spot",
  "sandbox": false,
  "symbols": ["BTCUSDT", "ETHUSDT", "ADAUSDT"]
}
```

**Response**:
```json
{
  "session_id": "session_a1b2c3d4e5f6_789xyz",
  "expires_at": "2025-01-16T10:30:00.000Z",
  "status": "active"
}
```

**Response Fields**:
- `session_id`: Unique session identifier for API access
- `expires_at`: Session expiration timestamp (ISO 8601)
- `status`: Session status (active, pending, expired, revoked)

## Performance Analytics Endpoints

### Get Performance Metrics

Retrieve comprehensive trading performance analytics for a session.

```http
GET /enclave/metrics/{sessionId}
```

**Path Parameters**:
- `sessionId`: Valid session identifier from credential submission

**Response**:
```json
{
  "metrics": {
    "totalReturn": 15.75,
    "totalReturnPct": 15.75,
    "totalReturnUsd": 157500.00,
    "sharpeRatio": 2.34,
    "sortinRatio": 3.12,
    "calmarRatio": 1.89,
    "maxDrawdown": -5.23,
    "maxDrawdownUsd": -52300.00,
    "volatility": 18.45,
    "beta": 1.12,
    "alpha": 2.34,
    "informationRatio": 1.67,
    "treynorRatio": 14.2,
    "totalVolume": 2500000.00,
    "totalTrades": 1247,
    "winRate": 68.5,
    "profitFactor": 2.15,
    "averageWin": 1250.75,
    "averageLoss": -580.25,
    "largestWin": 15000.00,
    "largestLoss": -7500.00,
    "totalFees": 12450.00,
    "periodStart": "2025-01-01T00:00:00.000Z",
    "periodEnd": "2025-01-15T23:59:59.999Z"
  },
  "assetBreakdown": [
    {
      "symbol": "BTCUSDT",
      "allocation": 45.2,
      "return": 12.8,
      "returnUsd": 64000.00,
      "volume": 1125000.00,
      "trades": 456,
      "fees": 5625.00
    },
    {
      "symbol": "ETHUSDT", 
      "allocation": 32.1,
      "return": 18.9,
      "returnUsd": 60600.00,
      "volume": 802500.00,
      "trades": 389,
      "fees": 4012.50
    }
  ],
  "riskMetrics": {
    "valueAtRisk95": -25000.00,
    "valueAtRisk99": -45000.00,
    "expectedShortfall": -35000.00,
    "skewness": -0.23,
    "kurtosis": 3.45,
    "correlation": {
      "BTCUSDT": 1.00,
      "ETHUSDT": 0.78
    }
  },
  "session_expires": "2025-01-16T10:30:00.000Z",
  "last_updated": "2025-01-15T15:45:30.000Z"
}
```

### Get Performance Summary

Retrieve summarized performance metrics optimized for dashboards.

```http
GET /enclave/summary/{sessionId}
```

**Path Parameters**:
- `sessionId`: Valid session identifier from credential submission

**Response**:
```json
{
  "summary": {
    "totalReturnPct": 15.75,
    "totalReturnUsd": 157500.00,
    "sharpeRatio": 2.34,
    "maxDrawdown": -5.23,
    "volatility": 18.45,
    "totalVolume": 2500000.00,
    "totalTrades": 1247,
    "winRate": 68.5,
    "currentValue": 1157500.00,
    "initialValue": 1000000.00
  },
  "status": {
    "session_id": "session_a1b2c3d4e5f6_789xyz",
    "expires_at": "2025-01-16T10:30:00.000Z",
    "data_freshness": "real-time",
    "last_trade": "2025-01-15T15:42:18.000Z"
  },
  "session_expires": "2025-01-16T10:30:00.000Z"
}
```

### Get Detailed Trade History

Retrieve aggregated trade history with privacy-preserving analytics.

```http
GET /enclave/trades/{sessionId}
```

**Query Parameters**:
- `limit`: Maximum number of records (default: 100, max: 1000)
- `offset`: Number of records to skip (default: 0)
- `symbol`: Filter by trading symbol (optional)
- `start_date`: Filter trades after date (ISO 8601)
- `end_date`: Filter trades before date (ISO 8601)

**Response**:
```json
{
  "trades": [
    {
      "id": "trade_12345_abc",
      "symbol": "BTCUSDT",
      "side": "buy",
      "quantity": 0.5,
      "price": 50000.00,
      "value": 25000.00,
      "fee": 12.50,
      "timestamp": "2025-01-15T14:30:15.000Z",
      "pnl": 750.00,
      "pnl_pct": 3.0
    }
  ],
  "pagination": {
    "total": 1247,
    "limit": 100,
    "offset": 0,
    "has_more": true
  },
  "session_expires": "2025-01-16T10:30:00.000Z"
}
```

## Session Management

### Session Renewal

Extend an existing session's time-to-live.

```http
POST /enclave/renew/{sessionId}
```

**Request Body**:
```json
{
  "ttl": 86400
}
```

**Response**:
```json
{
  "session_id": "session_a1b2c3d4e5f6_789xyz",
  "expires_at": "2025-01-16T10:30:00.000Z",
  "status": "active"
}
```

### Session Revocation

Immediately revoke a session and purge all associated data.

```http
DELETE /enclave/revoke/{sessionId}
```

**Response**:
```json
{
  "success": true,
  "message": "Session successfully revoked and data purged",
  "revoked_at": "2025-01-15T15:45:30.000Z"
}
```

### Session Cleanup

Trigger manual cleanup of expired sessions (administrative endpoint).

```http
POST /enclave/cleanup
```

**Response**:
```json
{
  "cleaned_sessions": 15,
  "cleanup_timestamp": "2025-01-15T15:45:30.000Z"
}
```

## System Status Endpoints

### Health Check

Check service health and enclave status.

```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T15:45:30.000Z",
  "services": {
    "enclave": "healthy",
    "database": "healthy",
    "exchanges": {
      "binance": "healthy",
      "coinbase": "healthy"
    }
  },
  "version": "1.0.0",
  "uptime": 86400
}
```

### Service Metrics

Get operational metrics (administrative endpoint).

```http
GET /metrics
```

**Response**:
```json
{
  "sessions": {
    "active": 25,
    "total_created": 1247,
    "total_expired": 1198,
    "total_revoked": 24
  },
  "performance": {
    "avg_response_time": 125,
    "requests_per_second": 45.2,
    "error_rate": 0.02
  },
  "enclave": {
    "memory_usage": 67.5,
    "cpu_usage": 23.1,
    "attestation_status": "valid"
  }
}
```

## Error Handling

### Error Response Format

```json
{
  "error": "invalid_session",
  "message": "Session has expired or is invalid",
  "code": "SESSION_EXPIRED",
  "timestamp": "2025-01-15T15:45:30.000Z",
  "request_id": "req_abc123def456"
}
```

### HTTP Status Codes

| Status Code | Meaning | Description |
|-------------|---------|-------------|
| `200` | OK | Request successful |
| `201` | Created | Resource created successfully |
| `400` | Bad Request | Invalid request parameters |
| `401` | Unauthorized | Invalid or expired session |
| `403` | Forbidden | Insufficient permissions |
| `404` | Not Found | Resource not found |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server error |
| `503` | Service Unavailable | Service temporarily unavailable |

### Common Error Codes

| Error Code | Description |
|------------|-------------|
| `INVALID_SESSION` | Session ID is invalid or expired |
| `ENCRYPTION_ERROR` | Failed to decrypt credential envelope |
| `ATTESTATION_FAILED` | Enclave attestation verification failed |
| `RATE_LIMIT_EXCEEDED` | Too many requests from client |
| `EXCHANGE_ERROR` | Error communicating with exchange API |
| `INSUFFICIENT_PERMISSIONS` | API key lacks required permissions |
| `SESSION_EXPIRED` | Session has reached its TTL |
| `INVALID_CREDENTIALS` | Exchange rejected provided credentials |

## Rate Limiting

### Default Limits
- **Authentication**: 10 requests per minute per IP
- **Metrics**: 100 requests per minute per session
- **Management**: 20 requests per minute per session

### Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642694400
```

## Client Libraries

### Node.js/TypeScript
```bash
npm install @perf-aggregator/client
```

```typescript
import { SecureClient } from '@perf-aggregator/client';

const client = new SecureClient({
  enclaveUrl: 'https://perf-aggregator.company.com',
  userId: 'institutional-trader-001',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  apiSecret: process.env.BINANCE_SECRET
});

const metrics = await client.getMetrics();
```

### Python
```bash
pip install perf-aggregator-client
```

```python
from perf_aggregator import SecureClient

client = SecureClient(
    enclave_url='https://perf-aggregator.company.com',
    user_id='institutional-trader-001',
    exchange='binance',
    api_key=os.getenv('BINANCE_API_KEY'),
    api_secret=os.getenv('BINANCE_SECRET')
)

metrics = client.get_metrics()
```

## WebSocket API (Real-time Updates)

### Connection
```javascript
const ws = new WebSocket('wss://perf-aggregator.company.com/ws');

// Authentication required
ws.send(JSON.stringify({
  type: 'auth',
  session_id: 'session_a1b2c3d4e5f6_789xyz'
}));
```

### Real-time Events
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'performance_update':
      updateDashboard(data.metrics);
      break;
    case 'trade_execution':
      logNewTrade(data.trade);
      break;
    case 'session_expiry_warning':
      showExpiryWarning(data.expires_in);
      break;
  }
};
```

## Security Considerations

### Credential Encryption
- Use the provided client libraries for proper credential encryption
- Verify enclave attestation before submitting credentials
- Never transmit plaintext credentials over any channel

### Session Management
- Store session IDs securely and never log them
- Implement automatic session renewal for long-running applications
- Revoke sessions immediately when no longer needed

### Network Security
- Always use HTTPS/WSS in production
- Implement certificate pinning for enhanced security
- Use proper TLS configuration with modern cipher suites

---

**Support**: support@company.com  
**Security Contact**: security@company.com  
**Last Updated**: 2025-01-15
# Performance Aggregator Service - Usage Examples

## 🏠 **Available Environments**

### **1. Development Service (Local)**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "http://localhost:3000"
```

### **2. Staging Service**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://staging.perf-aggregator.com"
```

### **3. Production Service (Secure Enclave)**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com" -Secure
```

## 🔐 **Secure Registration (Recommended for Production)**

### **With TEE Enclave**
```powershell
# Registration with encryption and secure enclave
.\register-user.ps1 -UserId "institutional-trader-001" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com" -Secure
```

### **Different Account Types**
```powershell
# Spot trading account
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com"

# Futures trading account
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "futures" -ServiceUrl "https://perf-aggregator.com"

# Margin trading account
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "margin" -ServiceUrl "https://perf-aggregator.com"
```

## 📊 **Performance Metrics Consultation**

### **Global Summary**
```powershell
# PowerShell - Session-based access
$sessionId = "session_abc123_def456"
$summary = Invoke-RestMethod -Uri "https://perf-aggregator.com/enclave/summary/$sessionId"
Write-Host "Total Volume: $($summary.summary.totalVolume)"
Write-Host "Total Return: $($summary.summary.totalReturnPct)%"
Write-Host "Sharpe Ratio: $($summary.summary.sharpeRatio)"
```

### **Detailed Metrics**
```powershell
# PowerShell - Comprehensive analytics
$sessionId = "session_abc123_def456"
$metrics = Invoke-RestMethod -Uri "https://perf-aggregator.com/enclave/metrics/$sessionId"
foreach ($metric in $metrics.metrics) {
    Write-Host "$($metric.symbol): $($metric.returnPct)% return, $($metric.volume) volume"
}
```

### **cURL Examples**
```bash
# Get attestation quote
curl https://perf-aggregator.com/attestation/quote

# Get performance summary (requires valid session)
curl https://perf-aggregator.com/enclave/summary/session_abc123_def456

# Get detailed metrics (requires valid session)
curl https://perf-aggregator.com/enclave/metrics/session_abc123_def456
```

## 🌐 **Web Integration**

### **JavaScript (Secure Client)**
```javascript
import { SecureClient } from '@perf-aggregator/client';

// Initialize secure client
const client = new SecureClient({
  enclaveUrl: 'https://perf-aggregator.com',
  userId: 'institutional-trader-001',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  apiSecret: process.env.BINANCE_SECRET,
  sandbox: false
});

// Establish secure session
await client.register();

// Retrieve performance metrics
const metrics = await client.getMetrics();
console.log(`Total Volume: $${metrics.summary.totalVolume}`);
console.log(`Total Return: ${metrics.summary.totalReturnPct}%`);
console.log(`Sharpe Ratio: ${metrics.summary.sharpeRatio}`);

// Clean up session
await client.revoke();
```

### **Python Integration**
```python
import requests
import os

# Configuration
enclave_url = "https://perf-aggregator.com"
session_id = os.getenv('PERF_AGGREGATOR_SESSION_ID')

# Retrieve performance summary
response = requests.get(f'{enclave_url}/enclave/summary/{session_id}')
summary = response.json()

print(f"Total Volume: ${summary['summary']['totalVolume']:,.2f}")
print(f"Total Return: {summary['summary']['totalReturnPct']:.2f}%")
print(f"Sharpe Ratio: {summary['summary']['sharpeRatio']:.2f}")
print(f"Maximum Drawdown: {summary['summary']['maxDrawdown']:.2f}%")
```

### **Node.js Server Integration**
```javascript
const express = require('express');
const { SecureClient } = require('@perf-aggregator/client');

const app = express();

app.get('/portfolio/performance', async (req, res) => {
  try {
    const client = new SecureClient({
      enclaveUrl: process.env.ENCLAVE_URL,
      userId: req.user.traderId,
      exchange: 'binance',
      apiKey: req.user.apiKey,
      apiSecret: req.user.apiSecret
    });

    await client.register();
    const metrics = await client.getMetrics();
    await client.revoke();

    res.json({
      success: true,
      data: metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Performance metrics unavailable',
      message: error.message
    });
  }
});
```

## 🔧 **Environment Configuration**

### **PowerShell Environment**
```powershell
# Production environment configuration
$env:PERF_AGGREGATOR_URL = "https://perf-aggregator.com"
$env:BINANCE_API_KEY = "your-institutional-api-key"
$env:BINANCE_SECRET = "your-institutional-secret"
$env:TRADING_ENVIRONMENT = "production"

# Register with environment variables
.\register-user.ps1 `
  -UserId "institutional-trader-001" `
  -Exchange "binance" `
  -ApiKey $env:BINANCE_API_KEY `
  -Secret $env:BINANCE_SECRET `
  -ServiceUrl $env:PERF_AGGREGATOR_URL `
  -Secure
```

### **Docker Environment**
```bash
# Docker configuration for institutional deployment
export PERF_AGGREGATOR_URL="https://perf-aggregator.company.com"
export BINANCE_API_KEY="your-api-key"
export BINANCE_SECRET="your-secret"
export NODE_ENV="production"

# Run containerized client
docker run -d \
  --name perf-aggregator-client \
  -e PERF_AGGREGATOR_URL=$PERF_AGGREGATOR_URL \
  -e BINANCE_API_KEY=$BINANCE_API_KEY \
  -e BINANCE_SECRET=$BINANCE_SECRET \
  -e NODE_ENV=$NODE_ENV \
  perf-aggregator-client:latest
```

### **Kubernetes Deployment**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: trading-credentials
type: Opaque
data:
  api-key: <base64-encoded-api-key>
  api-secret: <base64-encoded-secret>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: perf-aggregator-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: perf-aggregator-client
  template:
    metadata:
      labels:
        app: perf-aggregator-client
    spec:
      containers:
      - name: client
        image: perf-aggregator-client:latest
        env:
        - name: PERF_AGGREGATOR_URL
          value: "https://perf-aggregator.company.com"
        - name: BINANCE_API_KEY
          valueFrom:
            secretKeyRef:
              name: trading-credentials
              key: api-key
        - name: BINANCE_SECRET
          valueFrom:
            secretKeyRef:
              name: trading-credentials
              key: api-secret
```

## 🚨 **Security Best Practices**

### **Production Recommendations**
- ✅ **Always use HTTPS** in production environments
- ✅ **Enable `-Secure` option** for encrypted credential transmission
- ✅ **Use API keys with minimal permissions** (read-only recommended)
- ✅ **Enable sandbox mode** for testing and validation
- ✅ **Implement certificate pinning** for enhanced security
- ✅ **Use hardware security keys** for administrative access
- ❌ **Never share credentials** or API keys
- ❌ **Never use localhost** in production environments
- ❌ **Never commit secrets** to version control

### **Recommended API Permissions**
```yaml
required_permissions:
  - read_trading_history
  - read_account_balance
  - read_open_orders
  
forbidden_permissions:
  - create_orders
  - cancel_orders
  - withdraw_funds
  - modify_account_settings
```

### **Network Security**
```bash
# Firewall configuration for client access
# Allow only necessary outbound connections
iptables -A OUTPUT -p tcp --dport 443 -d perf-aggregator.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d api.binance.com -j ACCEPT
iptables -A OUTPUT -j DROP

# DNS over HTTPS for enhanced privacy
export DNS_OVER_HTTPS=1
export DOH_SERVER="https://cloudflare-dns.com/dns-query"
```

## 📈 **Performance Monitoring**

### **Real-time Metrics Dashboard**
```javascript
// WebSocket connection for real-time updates
const ws = new WebSocket('wss://perf-aggregator.com/ws');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  
  if (update.type === 'performance_update') {
    updateDashboard({
      totalReturn: update.data.totalReturnPct,
      sharpeRatio: update.data.sharpeRatio,
      maxDrawdown: update.data.maxDrawdown,
      timestamp: update.timestamp
    });
  }
};
```

### **Automated Reporting**
```powershell
# Scheduled performance report generation
$schedule = New-ScheduledTaskTrigger -Daily -At "09:00"
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\generate-performance-report.ps1"

Register-ScheduledTask -TaskName "DailyPerformanceReport" -Trigger $schedule -Action $action
```

---

**Last Updated**: 2025-01-15  
**Version**: 1.0.0  
**Support**: support@company.com
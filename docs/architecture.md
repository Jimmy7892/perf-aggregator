# Secure Architecture - Perf-Aggregator

## **Problem Solved**

Users must **never** expose their trading credentials to your infrastructure. The secure architecture enables direct communication with the enclave, ensuring protection of sensitive data.

## **Recommended Architecture**

### **Secure Flow**
```
┌─────────────┐    Chiffré     ┌─────────────────────────────────────────┐    API REST    ┌─────────────┐
│   Client    │ ──────────────► │           ENCLAVE SÉCURISÉE             │ ──────────────► │  Exchange   │
│ (PowerShell)│                 │  ┌─────────────────────────────────────┐ │                 │ (Binance)   │
└─────────────┘                 │  │        Perf-Aggregator COMPLET      │ │                 └─────────────┘
       │                        │  │                                     │ │
       │                        │  │  • ExchangeConnector               │ │
       ▼                        │  │  • TradeAggregator                 │ │
┌─────────────┐                 │  │  • Métriques de performance        │ │
│ Credentials │                 │  │  • Credentials déchiffrés          │ │
│ Chiffrés    │                 │  │  • Sessions utilisateurs           │ │
└─────────────┘                 │  │  • API REST vers exchanges         │ │
                                │  └─────────────────────────────────────┘ │
                                └─────────────────────────────────────────┘
```

### **Components**

#### **1. Secure Client**
- **PowerShell** : `register-user.ps1 -Secure`
- **JavaScript** : `SecureClient` class
- **Encryption** : X25519 + AES-GCM
- **Attestation** : Enclave verification

#### **2. Enclave (Port 3000) - Complete Perf-Aggregator**
- **TEE** : Trusted Execution Environment
- **Perf-Aggregator** : Complete service in enclave
- **ExchangeConnector** : Trading data collection from exchanges
- **TradeAggregator** : Real-time performance metrics calculation
- **Credentials** : Secure decryption and storage
- **Sessions** : Temporary user session management
- **API** : Endpoints for performance metrics consultation

#### **3. Main Service (Port 5000) - Optional**
- **Public Interface** : For non-secure users
- **Proxy** : Redirection to enclave
- **Logs** : Audit and monitoring

## **Implementation**

### **1. Secure Registration**

```powershell
# PowerShell - Recommended
.\register-user.ps1 -UserId "trader-john" `
                    -Exchange "binance" `
                    -ApiKey "abc123..." `
                    -Secret "xyz789..." `
                    -ServiceUrl "https://perf-aggregator.com" `
                    -Secure
```

```javascript
// JavaScript - Recommended
const client = new SecureClient({
  enclaveUrl: 'https://perf-aggregator.com:3000',
  userId: 'trader-john',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  secret: process.env.BINANCE_SECRET
});

await client.register();
```

### **2. Metrics Retrieval**

```powershell
# Via secure session
$sessionId = "session_1234567890_abc123"
$metrics = Invoke-RestMethod -Uri "https://perf-aggregator.com:3000/enclave/summary/$sessionId"
```

```javascript
// Via secure client
const metrics = await client.getMetrics();
const summary = await client.getSummary();
```

## **Security**

### **Benefits**
- **Zero exposure** of credentials to your infrastructure
- **End-to-end encryption** of sensitive data
- **Temporary sessions** with automatic expiration
- **Cryptographic attestation** of enclave
- **Isolation** of sensitive data

### **Protection Against**
- **Man-in-the-middle** : TLS encryption + attestation
- **Credential theft** : API key encryption
- **Session hijacking** : Temporary sessions
- **Data leakage** : TEE isolation

## **Security Metrics**

### **Encryption**
- **Algorithm** : X25519 ECDH + AES-GCM
- **Key size** : 256 bits
- **Nonce** : 96 bits random

### **Sessions**
- **Duration** : 24h default (configurable)
- **Cleanup** : Automatic every hour
- **Renewal** : New session required

### **Attestation**
- **Type** : SGX Quote
- **Verification** : Cryptographic
- **Renewal** : At each connection

## **Deployment**

### **Enclave (Production)**
```bash
# Environment variables
ENCLAVE_PORT=3000
ENCLAVE_HOST=0.0.0.0
ENCLAVE_PRIVATE_KEY=/path/to/private.pem
ENCLAVE_PUBLIC_KEY=/path/to/public.pem

# Startup
node src/enclave-server.js
```

### **Main Service (Optional)**
```bash
# Environment variables
PORT=5000
HOST=0.0.0.0
BACKEND_URL=http://localhost:3000

# Startup
node src/server.js
```

## **Complete Workflow**

### **1. Registration**
1. Client retrieves enclave attestation
2. Client encrypts credentials
3. Client sends encrypted envelope to enclave
4. Enclave decrypts and validates credentials
5. Enclave creates temporary session
6. Enclave returns session ID

### **2. Data Collection and Processing**
1. **Enclave** uses credentials to connect to exchange
2. **Enclave** collects trading data via REST API (ExchangeConnector)
3. **Enclave** aggregates data in real-time (TradeAggregator)
4. **Enclave** calculates performance metrics (volume, return %, etc.)
5. **Enclave** stores results securely

### **3. Results Retrieval**
1. Client uses session ID to retrieve metrics
2. Enclave verifies session validity
3. Enclave returns aggregated data
4. Session expires automatically after TTL

## **Business Benefits**

### **For Users**
- **Maximum trust** : Credentials never exposed
- **Performance** : Direct communication with enclave
- **Transparency** : Cryptographic attestation
- **Flexibility** : Configurable temporary sessions

### **For Operators**
- **Reduced liability** : No access to credentials
- **Audit trail** : Cryptographic logs
- **Simplified maintenance** : Component isolation
- **Compliance** : Zero-trust architecture

## **Recommendations**

### **Production**
- Always use secure registration
- Configure short TTL for sessions
- Implement key rotation
- Enable session monitoring

### **Development**
- Use sandbox for testing
- Limit API permissions
- Test session retrieval
- Validate enclave attestation

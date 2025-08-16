# Enclave Architecture - Complete Perf-Aggregator

## **Key Concept**

**Perf-Aggregator COMPLETE** runs in the secure enclave. There is no separation between "enclave" and "main service" - the entire trading performance aggregation service is in the enclave!

## **Real Architecture**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCLAVE SÉCURISÉE (TEE)                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                PERF-AGGREGATOR COMPLET                      │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │              ExchangeConnector                      │   │ │
│  │  │  • Connexion aux exchanges (Binance, etc.)         │   │ │
│  │  │  • Polling adaptatif des données de trading        │   │ │
│  │  │  • Gestion des credentials déchiffrés              │   │ │
│  │  └─────────────────────────────────────────────────────┘   │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │              TradeAggregator                        │   │ │
│  │  │  • Agrégation des trades en temps réel             │   │ │
│  │  │  • Calcul des métriques (volume, return %, etc.)   │   │ │
│  │  │  • FIFO trade pairing                              │   │ │
│  │  └─────────────────────────────────────────────────────┘   │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │              Gestion des sessions                   │   │ │
│  │  │  • Déchiffrement des credentials                   │   │ │
│  │  │  • Sessions temporaires avec TTL                   │   │ │
│  │  │  • Authentification des clients                     │   │ │
│  │  └─────────────────────────────────────────────────────┘   │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │              API Métriques                          │   │ │
│  │  │  • /enclave/metrics/:sessionId                      │   │ │
│  │  │  • /enclave/summary/:sessionId                      │   │ │
│  │  │  • /attestation/quote                               │   │ │
│  │  └─────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ API REST
                                ▼
                    ┌─────────────────────┐
                    │     EXCHANGES       │
                    │  • Binance         │
                    │  • Coinbase        │
                    │  • Kraken          │
                    └─────────────────────┘
```

## **Data Flow**

### **1. User Registration**
```
Client → Enclave (encrypted credentials)
Enclave → Decrypts and stores credentials
Enclave → Creates temporary session
Enclave → Returns session ID
```

### **2. Trade Collection**
```
Enclave → Connects to exchanges
Enclave → Collects trades via REST API
Enclave → Aggregates in real-time
Enclave → Calculates metrics
```

### **3. Results Consultation**
```
Client → Enclave (session ID)
Enclave → Verifies valid session
Enclave → Returns metrics
```

## **Security**

### **Everything is in the enclave**
- **ExchangeConnector** : In the enclave
- **TradeAggregator** : In the enclave
- **Credentials** : Decrypted in the enclave
- **Metrics** : Calculated in the enclave
- **Sessions** : Managed in the enclave

### **External Client**
- **Send** : Encrypted credentials
- **Receive** : Metrics via session
- **No access** : To sensitive data

## **Deployment**

### **Single Enclave (Production)**
```bash
# The enclave contains ALL of Perf-Aggregator
ENCLAVE_PORT=3000
ENCLAVE_HOST=0.0.0.0

# Startup
node src/enclave-server.js
```

### **No Separate Service**
- **No main server** required
- **No proxy** required
- **Single enclave** = Complete Perf-Aggregator

## **Benefits**

### **Maximum Security**
- **Zero exposure** of sensitive data
- **Complete isolation** in the enclave
- **End-to-end encryption** of communications

### **Simplicity**
- **Single service** to deploy
- **Clear architecture** : everything in the enclave
- **Simplified maintenance**

## **Summary**

**Perf-Aggregator = Secure Enclave**

There is no "main service" and "separate enclave". The entire Perf-Aggregator service runs in the secure enclave, ensuring maximum protection of user data.

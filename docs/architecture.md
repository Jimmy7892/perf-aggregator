# Architecture Sécurisée - Perf-Aggregator

## 🎯 **Problème résolu**

Les utilisateurs ne doivent **jamais** exposer leurs API keys à votre serveur principal. L'architecture sécurisée permet une communication directe avec l'enclave.

## 🔐 **Architecture recommandée**

### **Flux sécurisé**
```
┌─────────────┐    Chiffré     ┌─────────────────────────────────────────┐    API REST    ┌─────────────┐
│   Client    │ ──────────────► │           ENCLAVE SÉCURISÉE             │ ──────────────► │  Exchange   │
│ (PowerShell)│                 │  ┌─────────────────────────────────────┐ │                 │ (Binance)   │
└─────────────┘                 │  │        Perf-Aggregator COMPLET      │ │                 └─────────────┘
       │                        │  │                                     │ │
       │                        │  │  • ExchangeConnector               │ │
       ▼                        │  │  • TradeAggregator                 │ │
┌─────────────┐                 │  │  • Métriques calculées             │ │
│ API Keys    │                 │  │  • Credentials déchiffrés          │ │
│ Chiffrées   │                 │  │  • Sessions utilisateurs           │ │
└─────────────┘                 │  │  • API REST vers exchanges         │ │
                                │  └─────────────────────────────────────┘ │
                                └─────────────────────────────────────────┘
```

### **Composants**

#### **1. Client sécurisé**
- **PowerShell** : `register-user.ps1 -Secure`
- **JavaScript** : `SecureClient` class
- **Chiffrement** : X25519 + AES-GCM
- **Attestation** : Vérification de l'enclave

#### **2. Enclave (Port 3000) - Perf-Aggregator complet**
- **TEE** : Trusted Execution Environment
- **Perf-Aggregator** : Service complet dans l'enclave
- **ExchangeConnector** : Collecte des trades depuis les exchanges
- **TradeAggregator** : Calcul des métriques en temps réel
- **Credentials** : Déchiffrement et stockage sécurisé
- **Sessions** : Gestion temporaire des sessions utilisateurs
- **API** : Endpoints pour consultation des métriques

#### **3. Service principal (Port 5000) - Optionnel**
- **Interface publique** : Pour les utilisateurs non-sécurisés
- **Proxy** : Redirection vers l'enclave
- **Logs** : Audit et monitoring

## 🚀 **Implémentation**

### **1. Enregistrement sécurisé**

```powershell
# PowerShell - Recommandé
.\register-user.ps1 -UserId "trader-john" `
                    -Exchange "binance" `
                    -ApiKey "abc123..." `
                    -Secret "xyz789..." `
                    -ServiceUrl "https://perf-aggregator.com" `
                    -Secure
```

```javascript
// JavaScript - Recommandé
const client = new SecureClient({
  enclaveUrl: 'https://perf-aggregator.com:3000',
  userId: 'trader-john',
  exchange: 'binance',
  apiKey: process.env.BINANCE_API_KEY,
  secret: process.env.BINANCE_SECRET
});

await client.register();
```

### **2. Récupération des métriques**

```powershell
# Via session sécurisée
$sessionId = "session_1234567890_abc123"
$metrics = Invoke-RestMethod -Uri "https://perf-aggregator.com:3000/enclave/summary/$sessionId"
```

```javascript
// Via client sécurisé
const metrics = await client.getMetrics();
const summary = await client.getSummary();
```

## 🔒 **Sécurité**

### **Avantages**
- ✅ **Zero exposition** des API keys au serveur principal
- ✅ **Chiffrement end-to-end** des credentials
- ✅ **Sessions temporaires** avec TTL automatique
- ✅ **Attestation cryptographique** de l'enclave
- ✅ **Isolation** des données sensibles

### **Protection contre**
- ❌ **Man-in-the-middle** : Chiffrement TLS + attestation
- ❌ **Credential theft** : Chiffrement des API keys
- ❌ **Session hijacking** : Sessions temporaires
- ❌ **Data leakage** : Isolation TEE

## 📊 **Métriques de sécurité**

### **Chiffrement**
- **Algorithme** : X25519 ECDH + AES-GCM
- **Taille clé** : 256 bits
- **Nonce** : 96 bits aléatoire

### **Sessions**
- **Durée** : 24h par défaut (configurable)
- **Nettoyage** : Automatique toutes les heures
- **Renouvellement** : Nouvelle session requise

### **Attestation**
- **Type** : SGX Quote
- **Vérification** : Cryptographique
- **Renouvellement** : À chaque connexion

## 🛠️ **Déploiement**

### **Enclave (Production)**
```bash
# Variables d'environnement
ENCLAVE_PORT=3000
ENCLAVE_HOST=0.0.0.0
ENCLAVE_PRIVATE_KEY=/path/to/private.pem
ENCLAVE_PUBLIC_KEY=/path/to/public.pem

# Démarrage
node src/enclave-server.js
```

### **Service principal (Optionnel)**
```bash
# Variables d'environnement
PORT=5000
HOST=0.0.0.0
BACKEND_URL=http://localhost:3000

# Démarrage
node src/server.js
```

## 🔄 **Workflow complet**

### **1. Enregistrement**
1. Client récupère l'attestation de l'enclave
2. Client chiffre ses credentials
3. Client envoie l'enveloppe chiffrée à l'enclave
4. Enclave déchiffre et valide les credentials
5. Enclave crée une session temporaire
6. Enclave retourne un session ID

### **2. Collecte et traitement des données**
1. **Enclave** utilise les credentials pour se connecter à l'exchange
2. **Enclave** collecte les trades via API REST (ExchangeConnector)
3. **Enclave** agrège les données en temps réel (TradeAggregator)
4. **Enclave** calcule les métriques de performance (volume, return %, etc.)
5. **Enclave** stocke les résultats de manière sécurisée

### **3. Récupération des résultats**
1. Client utilise son session ID pour récupérer les métriques
2. Enclave vérifie la validité de la session
3. Enclave retourne les données agrégées
4. Session expire automatiquement après TTL

## 📈 **Avantages business**

### **Pour les utilisateurs**
- 🔒 **Confiance maximale** : API keys jamais exposées
- ⚡ **Performance** : Communication directe avec l'enclave
- 🛡️ **Transparence** : Attestation cryptographique
- 🔄 **Flexibilité** : Sessions temporaires configurables

### **Pour les opérateurs**
- 🚫 **Responsabilité réduite** : Pas d'accès aux credentials
- 📊 **Audit trail** : Logs cryptographiques
- 🔧 **Maintenance simplifiée** : Isolation des composants
- 🎯 **Conformité** : Architecture zero-trust

## 🚨 **Recommandations**

### **Production**
- ✅ Utilisez **toujours** l'enregistrement sécurisé
- ✅ Configurez des **TTL courts** pour les sessions
- ✅ Implémentez la **rotation des clés**
- ✅ Activez le **monitoring des sessions**

### **Développement**
- ⚠️ Utilisez le **sandbox** pour les tests
- ⚠️ Limitez les **permissions API**
- ⚠️ Testez la **récupération de session**
- ⚠️ Validez l'**attestation de l'enclave**

# Architecture Enclave - Perf-Aggregator Complet

## 🎯 **Concept clé**

**Perf-Aggregator ENTIER** fonctionne dans l'enclave sécurisée. Il n'y a pas de séparation entre "enclave" et "service principal" - tout le service est dans l'enclave !

## 🏗️ **Architecture réelle**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCLAVE SÉCURISÉE (TEE)                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                PERF-AGGREGATOR COMPLET                      │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │              ExchangeConnector                      │   │ │
│  │  │  • Connexion aux exchanges (Binance, etc.)         │   │ │
│  │  │  • Polling adaptatif des trades                    │   │ │
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

## 🔄 **Flux de données**

### **1. Enregistrement utilisateur**
```
Client → Enclave (credentials chiffrés)
Enclave → Déchiffre et stocke credentials
Enclave → Crée session temporaire
Enclave → Retourne session ID
```

### **2. Collecte des trades**
```
Enclave → Se connecte aux exchanges
Enclave → Collecte trades via API REST
Enclave → Agrège en temps réel
Enclave → Calcule métriques
```

### **3. Consultation des résultats**
```
Client → Enclave (session ID)
Enclave → Vérifie session valide
Enclave → Retourne métriques
```

## 🛡️ **Sécurité**

### **Tout est dans l'enclave**
- ✅ **ExchangeConnector** : Dans l'enclave
- ✅ **TradeAggregator** : Dans l'enclave
- ✅ **Credentials** : Déchiffrés dans l'enclave
- ✅ **Métriques** : Calculées dans l'enclave
- ✅ **Sessions** : Gérées dans l'enclave

### **Client externe**
- 🔒 **Envoi** : Credentials chiffrés
- 🔒 **Réception** : Métriques via session
- 🔒 **Pas d'accès** : Aux données sensibles

## 🚀 **Déploiement**

### **Enclave unique (Production)**
```bash
# L'enclave contient TOUT Perf-Aggregator
ENCLAVE_PORT=3000
ENCLAVE_HOST=0.0.0.0

# Démarrage
node src/enclave-server.js
```

### **Pas de service séparé**
- ❌ **Pas de serveur principal** nécessaire
- ❌ **Pas de proxy** nécessaire
- ✅ **Enclave unique** = Perf-Aggregator complet

## 📊 **Avantages**

### **Sécurité maximale**
- 🔒 **Zero exposition** des données sensibles
- 🔒 **Isolation complète** dans l'enclave
- 🔒 **Chiffrement end-to-end** des communications

### **Simplicité**
- 🎯 **Un seul service** à déployer
- 🎯 **Architecture claire** : tout dans l'enclave
- 🎯 **Maintenance simplifiée**

## 🎯 **Résumé**

**Perf-Aggregator = Enclave sécurisée**

Il n'y a pas de "service principal" et "enclave séparée". Tout le service Perf-Aggregator fonctionne dans l'enclave sécurisée, garantissant une protection maximale des données utilisateur.

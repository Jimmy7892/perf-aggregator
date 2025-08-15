# Secure TEE Enclave Backend Service

Service backend sécurisé qui accepte des clés API chiffrées, les transmet à une enclave TEE (ou simulateur en dev), calcule des agrégats et fournit des résultats signés. **Contrainte cruciale : aucune rétention de secrets en clair.**

## 🛡️ Sécurité

### Principe fondamental
- **INTERDIT ABSOLU** : stocker des API keys/secrets en clair dans la DB, logs, fichiers, snapshots
- **AUTORISÉ** : stocker ciphertext, ephemeral_pub, nonce, tag, metadata non sensibles, TTL, session_id, agrégats signés

### Architecture sécurisée
- Les données déchiffrées n'existent qu'en mémoire de l'enclave
- DB chiffrée au repos (PG with TDE or disk encryption)
- Accès DB limités par RBAC
- TTL/auto-delete sur ciphertexts + endpoints de révocation

## 🚀 Vérification en 60 secondes

### Prérequis
```bash
# PostgreSQL en cours d'exécution
# Node.js 18+ installé
```

### 1. Installation
```bash
npm install
npm run build
```

### 2. Configuration DB
```bash
# Configurer la base de données
export DATABASE_URL="postgresql://username:password@localhost:5432/perf_aggregator"

# Migrer le schéma
npm run migrate
```

### 3. Démarrage du service
```bash
npm run start:enclave
# Service démarré sur http://localhost:3000
```

### 4. Test de vérification
```bash
# Vérifier l'attestation
curl http://localhost:3000/attestation/quote

# Réponse attendue :
# {
#   "quote": "base64...",
#   "enclave_pubkey": "base64...", 
#   "image_hash": "mock-hash..."
# }
```

### 5. Test complet (avec client)
```javascript
// Exemple d'utilisation côté client
import { CryptoHelper } from './src/client/crypto-helper.js';

// 1. Vérifier l'attestation
const attestation = await fetch('/attestation/quote').then(r => r.json());
const verification = await CryptoHelper.verifyAttestation(attestation, attestation.image_hash);

// 2. Chiffrer les credentials
const encrypted = await CryptoHelper.encryptCredentials({
  exchange: 'binance',
  apiKey: 'your-api-key',
  apiSecret: 'your-secret'
}, attestation.enclave_pubkey);

// 3. Soumettre à l'enclave
const response = await fetch('/enclave/submit_key', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ...encrypted,
    metadata: { exchange: 'binance', label: 'main', ttl: 3600 }
  })
});

const { session_id } = await response.json();

// 4. Demander les agrégats
const aggregates = await fetch('/enclave/request_aggregates', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ session_id })
}).then(r => r.json());

console.log('Agrégats signés:', aggregates.aggregates_signed);
```

## 📋 API Endpoints

### `GET /attestation/quote`
Retourne la quote d'attestation et la clé publique de l'enclave
```json
{
  "quote": "string (base64)",
  "enclave_pubkey": "string (base64)", 
  "image_hash": "string"
}
```

### `POST /enclave/submit_key`
Soumet des clés API chiffrées à l'enclave
```json
{
  "ephemeral_pub": "B64(...)",
  "nonce": "B64(...)", 
  "ciphertext": "B64(...)",
  "tag": "B64(...)",
  "metadata": {
    "exchange": "binance",
    "label": "main", 
    "ttl": 86400
  }
}
```

### `POST /enclave/request_aggregates`
Demande les agrégats signés pour une session
```json
{
  "session_id": "uuid"
}
```

### `POST /enclave/revoke`
Révoque une session et purge toutes les données
```json
{
  "session_id": "uuid" 
}
```

## 🔧 Configuration

### Variables d'environnement
```bash
# Port du service enclave (défaut: 3000)
ENCLAVE_PORT=3000

# URL de la base de données
DATABASE_URL=postgresql://localhost:5432/perf_aggregator

# TTL maximum en secondes (défaut: 7 jours)
MAX_TTL_SECONDS=604800

# Limites de taux (défaut: 100 req/15min)
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=900000

# Origins autorisées pour CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### Commandes disponibles
```bash
npm run build          # Compiler TypeScript
npm run start          # Démarrer le service d'agrégation original
npm run start:enclave  # Démarrer le service enclave sécurisé
npm run migrate        # Migrer la base de données
npm run test           # Tests unitaires et d'intégration
npm run dev            # Mode développement avec watch
```

## 🗄️ Schéma de base de données

### Tables principales
- **users** : Métadonnées utilisateur (email, status)
- **sessions** : Sessions d'enclave (exchange, label, TTL, status)  
- **credentials** : **Données chiffrées uniquement** (ephemeral_pub, nonce, ciphertext, tag)
- **aggregates** : Résultats agrégés signés (visibles aux opérateurs)
- **merkle_logs** : Preuves de vérification Merkle
- **ops_logs** : Logs d'opérations non sensibles

### Sécurité DB
- Rôle `operator_readonly` : accès en lecture seule SANS accès à `credentials`
- Rôle `app_service` : accès limité pour l'application
- Contraintes de validation sur les formats base64
- Fonction TTL automatique pour nettoyer les credentials expirés

## 🧪 Tests

### Tests de sécurité critiques
```bash
npm test
```

Les tests vérifient :
- ✅ Aucun secret en clair dans la DB
- ✅ Chiffrement/déchiffrement correct
- ✅ Isolation des sessions
- ✅ Purge complète lors de la révocation
- ✅ Validation des entrées
- ✅ Limites de taux

### Tests d'intégration E2E
- Flux complet client → enclave → DB
- Vérification qu'aucun plaintext n'apparaît
- Test de révocation et purge

## 🏭 Production

### Remplacement de l'enclave mock
En production, remplacer `MockEnclaveService` par :
- **AWS Nitro Enclaves** : pour AWS
- **Intel SGX** : pour environnements on-premise
- **Azure Confidential Computing** : pour Azure
- **Google Confidential GKE** : pour GCP

### Sécurité production
1. **Chiffrement au repos** : Activer TDE sur PostgreSQL
2. **mTLS** : Communications service ↔ enclave
3. **Attestation réelle** : Vérification hardware des quotes
4. **Surveillance** : Monitoring des accès et opérations
5. **Builds reproductibles** : Hash d'images vérifiables

### Déploiement
```bash
# Build de l'image
docker build -t secure-enclave-backend .

# Déploiement avec variables sécurisées
docker run -d \
  -p 3000:3000 \
  -e DATABASE_URL=$SECURE_DB_URL \
  -e ENCLAVE_PORT=3000 \
  secure-enclave-backend
```

## 📊 Monitoring

### Métriques importantes
- Nombre de sessions actives
- Latence des opérations d'enclave
- Taux d'erreur de chiffrement/déchiffrement
- Fréquence du nettoyage TTL
- Tentatives d'accès non autorisées

### Logs de sécurité
- Toutes les opérations d'enclave sont loggées (sans données sensibles)
- Tentatives d'accès à la table `credentials` sont auditées
- Erreurs de validation d'entrée sont tracées

## ⚠️ Avertissements

1. **DEV ONLY** : L'implémentation actuelle utilise un mock d'enclave
2. **Remplacer en production** : Implémenter une vraie enclave TEE
3. **Vérification d'attestation** : Implémenter la vérification réelle des quotes
4. **Clés de développement** : Remplacer toutes les clés par des vraies clés sécurisées
5. **RBAC** : Ajouter l'authentification pour les endpoints d'opérateur

## 📞 Support

Pour toute question de sécurité ou d'implémentation, consultez :
- La documentation des tests dans `src/__tests__/`
- Les interfaces d'enclave dans `src/enclave/`
- Les exemples d'usage dans `src/client/crypto-helper.ts`
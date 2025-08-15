# Aggregator Service

Service dagrégation temps réel: collecte de trades via API REST optimisée, agrégation en mémoire, signature ED25519 et envoi vers une API dingestion compatible (vendorneutral).

## Architecture

- **API REST** : Récupération des trades depuis les exchanges (polling optimisé avec retry)
- **WebSocket** : Interface temps réel pour les clients (optionnel)
- **TEE Enclave** : Traitement sécurisé des données sensibles
- **Signature ED25519** : Intégrité cryptographique des agrégations

## Configuration

### Variables d'environnement
- AGGREGATOR_PORT (défaut: 5000)
- AGGREGATOR_WS_PORT (défaut: 5010)
- AGGREGATOR_BACKEND_URL (URL de lAPI dingestion; ex: http://localhost:3010)
- AGGREGATOR_PRIVATE_KEY (chemin de la clé privée ED25519 montée en volume)

### Configuration des exchanges
- `apiInterval` : Intervalle entre les appels API (défaut: 60000ms)
- `maxRetries` : Nombre de tentatives en cas d'échec (défaut: 3)
- `accountType` : Type de compte à surveiller ('spot', 'futures', 'margin')
- `sandbox` : Utiliser l'environnement de test
- **Détection automatique** : Tous les symboles tradés sont détectés automatiquement

## Build & exécution

`ash
pnpm i
pnpm build
pnpm start
`

## Docker

`ash
docker build -t perf-aggregator:latest .
docker run -p 5000:5000 -p 5010:5010 \
  -e AGGREGATOR_BACKEND_URL=http://host.docker.internal:3010 \
  -e AGGREGATOR_PRIVATE_KEY=/app/ed25519_private.key \
  --mount type=bind,source=/abs/path/ed25519_private.key,target=/app/ed25519_private.key,readonly \
  perf-aggregator:latest
`

## API du service

HTTP:
- GET /health
- POST /jobs
- GET /jobs/:jobId
- POST /jobs/:jobId/process

WebSocket:
- ws://localhost:{AGGREGATOR_WS_PORT}/ws/{jobId}

Format trade:
`json
{  type: trade, data: { symbol: BTCUSDT, price: 50000, size: 0.1, side: buy, timestamp: 1640995200000, fee: 1.5 } }
`

## Contrat dingestion (backend cible)

- Méthode: POST {AGGREGATOR_BACKEND_URL}/api/ingest
- ContentType: pplication/json
- Corps: objet signé ED25519, par exemple:

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


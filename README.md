# Aggregator Service

Service d’agrégation temps réel: collecte de trades via WebSocket, agrégation en mémoire, signature ED25519 et transmission au backend d’ingestion.

## Configuration (env)

- `AGGREGATOR_PORT` (defaut: 5000)
- `AGGREGATOR_WS_PORT` (defaut: 5010)
- `AGGREGATOR_BACKEND_URL` (defaut: http://localhost:3010)
- `AGGREGATOR_PRIVATE_KEY` (chemin privé ED25519 monté en volume)

## Démarrage

```powershell
pnpm i && pnpm build
pnpm start
```

## API

HTTP:
- `GET /health`
- `POST /jobs`
- `GET /jobs/:jobId`
- `POST /jobs/:jobId/process`

WebSocket:
- `ws://localhost:{AGGREGATOR_WS_PORT}/ws/{jobId}`

Message trade:
```json
{ "type": "trade", "data": { "symbol": "BTCUSDT", "price": 50000, "size": 0.1, "side": "buy", "timestamp": 1640995200000, "fee": 1.5 } }
```

## Sécurité

- Clé privée ED25519 uniquement en mémoire et montée par volume
- Données agrégées uniquement (pas de rétention de trades bruts)

## Docker

```bash
docker build -t aggregator -f Dockerfile ../../
docker run -p 5000:5000 -p 5010:5010 aggregator
```


# syntax=docker/dockerfile:1.7
FROM node:20.14.0-alpine AS base
WORKDIR /app

FROM base AS build
RUN corepack enable && corepack prepare pnpm@9.6.0 --activate
WORKDIR /app
COPY services/aggregator/package-prod.json /app/package.json
COPY services/aggregator/tsconfig.json /app/tsconfig.json
COPY services/aggregator/src /app/src
RUN pnpm i --frozen-lockfile=false
RUN pnpm build || npx tsc -p tsconfig.json

FROM base AS runner
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json /app/package.json
RUN npm install --production
COPY --from=build /app/dist/ /app/dist/
COPY services/aggregator/config.yml /app/config.yml
# Do not include private keys in image. Mount at runtime:
#   -v $PWD/services/aggregator/ed25519_private.key:/app/ed25519_private.key:ro
ENTRYPOINT ["node","/app/dist/src/server.js"]


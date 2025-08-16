# syntax=docker/dockerfile:1.7
FROM node:20.14.0-alpine AS base
WORKDIR /app

FROM base AS build
RUN corepack enable && corepack prepare pnpm@9.6.0 --activate
WORKDIR /app
COPY package.json /app/package.json
COPY pnpm-lock.yaml /app/pnpm-lock.yaml
COPY tsconfig.json /app/tsconfig.json
COPY src /app/src
RUN pnpm install --frozen-lockfile
RUN pnpm build

FROM base AS runner
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json /app/package.json
RUN npm install --production
COPY --from=build /app/dist/ /app/dist/
COPY config.yml /app/config.yml
# Security: Do not include private keys in image. Mount at runtime:
#   -v $PWD/keys/ed25519_private.key:/app/keys/ed25519_private.key:ro
EXPOSE 3000
ENTRYPOINT ["node", "/app/dist/src/server.js"]


# 1. Base → Bun runtime base
FROM oven/bun:1.3.13 AS base
WORKDIR /app

# 2. Pruner → Turbo prune monorepo
FROM base AS pruner
COPY . .
RUN bunx turbo prune @tamtt-labs/web-app --docker

# 3. Builder → Build
FROM base AS builder
COPY --from=pruner /app/out/json/ .
RUN bun install

COPY --from=pruner /app/out/full/ .
COPY turbo.json turbo.json
RUN bun turbo run build

# 4. Runner → Final production image (Ultra-slim)
FROM oven/bun:1.3.13-distroless AS runner
WORKDIR /app

# Copy only the compiled output from the builder
COPY --from=builder /app/apps/frontend/web-app/.output .

# Set environment variables
ENV NODE_ENV=production
EXPOSE 3000

CMD ["./server/index.mjs"]

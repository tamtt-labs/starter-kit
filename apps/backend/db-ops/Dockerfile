# 1. Base → Bun runtime base
FROM oven/bun:1.3.13 AS base
WORKDIR /app

# 2. Pruner → Turbo prune monorepo
FROM base AS pruner
COPY . .
RUN bunx turbo prune @tamtt-labs/db-ops --docker

# 3. Builder → Build backend as binary
FROM base AS builder
COPY --from=pruner /app/out/json/ .
RUN bun install

COPY --from=pruner /app/out/full/ .
COPY turbo.json turbo.json
RUN bun turbo run build

# 4. Runner → Final production image (Ultra-slim)
# We use 'gcr.io/distroless/base' because the binary needs minimal system libs (libc)
FROM gcr.io/distroless/base-debian12 AS runner
WORKDIR /app

# Copy only the compiled binary from the builder
COPY --from=builder /app/apps/backend/db-ops/dist/db-ops ./db-ops
COPY --from=builder /app/apps/backend/db-ops/migrations ./migrations

# Set environment variables
ENV NODE_ENV=production
EXPOSE 3000

# Run the standalone binary directly
CMD ["./db-ops"]

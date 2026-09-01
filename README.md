# Turborepo Starter Kit

A Turbo monorepo starter kit using T3-style architecture with a NestJS backend, Next.js frontend, and Rust crates for shared logic.

## Structure

```
starter-kit/
├── apps/
│   ├── backend/
│   │   ├── api-gateway/     # NestJS API Gateway
│   │   └── db-ops/          # Database operations / migrations
│   └── frontend/
│       └── web-app/         # Next.js Vite React SSR app
├── packages/
│   ├── backend/
│   │   ├── cqrs/            # CQRS library
│   │   └── ddd/             # DDD library
│   ├── frontend/
│   │   └── design-system/   # UI component library
│   └── shared/
│       ├── tsdown/          # Shared bundler config
│       └── tsconfig/        # Shared TypeScript config
```

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/)
- Docker (for database)

### Setup

```bash
# Install dependencies
bun install

# Start the database
docker compose up -d tamtt-postgres

# Run migrations
bun --filter db-ops run migration:generate

# Start services
bun --filter api-gateway start
bun --filter web-app dev
```

### Environment Variables

Each service has its own `.env.example` file in the root of its directory. Copy the relevant one and adjust:

- `apps/backend/api-gateway/.env.example` — API gateway config
- `apps/backend/db-ops/.env.example` — Database migration config
- `apps/frontend/web-app/.env.example` — Web app config

### Building

```bash
bun run build:all
```

### Developing

```bash
bun run dev:all
```

## Technologies

- **Backend:** NestJS + Elysia
- **Frontend:** Next.js + Vite + React SSR
- **Shared Logic:** Rust crates (`packages/shared/*`)
- **Database:** PostgreSQL
- **Package Manager:** Bun
- **Build Tool:** Turborepo

## License

MIT

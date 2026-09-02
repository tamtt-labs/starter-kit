# Starter Kit

A TypeScript monorepo built with [Turborepo](https://turborepo.dev) and [Bun](https://bun.sh) workspaces, organized around a DDD + CQRS backend and a React frontend.

## Requirements

- **Bun** `1.4.0` (required — see `engines` in the root `package.json`)
- **Docker** (optional, for the local Postgres database)

## Getting started

```bash
bun install
docker compose up -d   # start the Postgres database
bun run dev            # run all apps/packages in watch mode
```

## Repository structure

```
apps/
  backend/
    api-gateway/          @tamtt-labs/api-gateway  — API service (Elysia, Drizzle, better-auth)
    db-ops/               @tamtt-labs/db-ops       — CLI for database migrations & ops (commander)
  frontend/
    web-app/              @tamtt-labs/web-app      — Vite + React frontend (TanStack Start, Tailwind)
packages/
  backend/
    ddd/                  @tamtt-labs/ddd          — DDD primitives (entities, domain services)
    cqrs/                 @tamtt-labs/cqrs         — CQRS/ES building blocks (command/query buses, event bus, aggregate root)
  frontend/
    design-system/        @tamtt-labs/design-system — Shared UI components (shadcn/ui)
  shared/
    tsconfig/             @tamtt-labs/tsconfig     — Shared TypeScript configs
    tsdown/               Shared tsdown build configuration
```

### Apps

- **api-gateway** — the backend API. Uses [Elysia](https://elysiajs.com) for routing, [Drizzle ORM](https://orm.drizzle.team) for persistence, and [better-auth](https://better-auth.com) (with passkey support) for authentication. Module code lives in `src/core/modules/`.

  ```bash
  cd apps/backend/api-gateway
  bun run dev                        # dev server with watch mode
  bun run migration:generate         # generate a Drizzle migration
  bun run migration:run              # apply migrations
  ```

- **db-ops** — a CLI (built on `commander`) for database operations, including running migrations.

- **web-app** — a [TanStack Start](https://tanstack.com/start) app (Vite + React 19) using Tailwind CSS and the shared `design-system` package.

### Packages

- **ddd** — domain-driven design primitives shared by the backend apps.
- **cqrs** — CQRS/event-sourcing infrastructure: command/query buses, event bus, event publisher, aggregate roots, and related classes.
- **design-system** — the shared component library (shadcn/ui-based) used by frontend apps.
- **tsconfig** / **tsdown** — shared TypeScript and build configuration.

## Common commands (run from the repo root)

| Command                         | Description                                                   |
| ------------------------------- | ------------------------------------------------------------- |
| `bun run dev`                   | Run all apps/packages in dev mode (via Turbo)                 |
| `bun run build`                 | Build everything (via Turbo)                                  |
| `bun run typecheck`             | Type-check all packages (via Turbo)                           |
| `bun run lint` / `lint:fix`     | Lint with [Oxlint](https://github.com/oxc-project/oxc)        |
| `bun run format` / `format:fix` | Check/format with [Oxfmt](https://github.com/oxc-project/oxc) |

Each package can also be targeted individually, e.g. `bun run dev --filter @tamtt-labs/web-app`.

## Tooling

- [Turborepo](https://turborepo.dev) — task orchestration and caching (`turbo.json`)
- [tsdown](https://tsdown.dev) — package builds; backend apps compile to standalone binaries via `bun build --compile`
- [Oxlint](https://oxc.rs/docs/guide/usage/linter.html) / [Oxfmt](https://oxc.rs/docs/guide/usage/formatter.html) — linting and formatting
- [Husky](https://typicode.github.io/husky/) + [lint-staged](https://github.com/lint-staged/lint-staged) — pre-commit hooks
- [Docker Compose](docker-compose.yml) — local `pgvector/pgvector:pg18` database (port `5432`)

## Testing

Backend packages run their tests with [Bun's test runner](https://bun.sh/docs/test-intro):

```bash
cd apps/backend/api-gateway
bun test
```

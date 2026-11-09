#!/usr/bin/env bash
# Live demo from a fresh database: reset Postgres, start the stack, load the recorded-fixture reports (the
# fallback that needs no network), then run the brief's cases live. Usage: scripts/demo.sh [compose project]
set -euo pipefail
cd "$(dirname "$0")/.."
P="${1:-cybermatrix}"
start=$(date +%s)
docker compose -p "$P" down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$P" up -d >/dev/null
for _ in $(seq 1 60); do curl -sf http://localhost:8000/health >/dev/null && break; sleep 2; done
(cd backend && DATABASE_URL=postgresql+asyncpg://cybermatrix:cybermatrix@localhost:${POSTGRES_PORT:-5432}/cybermatrix \
  uv run python -m demo.seed)
(cd backend && uv run python -m demo.live "${@:2}")
echo "demo.sh finished in $(( $(date +%s) - start ))s. Open http://localhost:3000/clusters and the report links above."

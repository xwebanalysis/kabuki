#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Stopping containers..."
docker compose -f "$ROOT_DIR/docker-compose.yml" down --volumes --remove-orphans 2>/dev/null || true

echo "Removing local artifacts..."
rm -rf "$ROOT_DIR/backend/.venv"
rm -f "$ROOT_DIR/backend/kabuki.db" "$ROOT_DIR/backend/kabuki.db-wal" "$ROOT_DIR/backend/kabuki.db-shm"
rm -rf "$ROOT_DIR/backend/.pytest_cache"
find "$ROOT_DIR/backend" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$ROOT_DIR/frontend/node_modules"
rm -rf "$ROOT_DIR/frontend/dist"
rm -rf "$ROOT_DIR/frontend/.angular"

echo "Clean."

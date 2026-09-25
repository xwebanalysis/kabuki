#!/usr/bin/env bash
# Kabuki launcher — local (SQLite, default) or docker (PostgreSQL) mode.
set -euo pipefail

# Prefer the mise-managed Node 24 LTS for Angular tooling (system Node may be unsupported)
if [ -d "$HOME/.local/share/mise/installs/node/24/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/share/mise/installs/node/24/bin:"*) ;;
        *) export PATH="$HOME/.local/share/mise/installs/node/24/bin:$PATH" ;;
    esac
fi

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL="kabuki"
BACKEND_PORT="${KABUKI_BACKEND_PORT:-8040}"
FRONTEND_PORT="${KABUKI_FRONTEND_PORT:-4240}"
DB_PATH="${KABUKI_DB_PATH:-$ROOT_DIR/backend/kabuki.db}"
XWA_SDK_LOCAL="${XWA_SDK_DIR:-$ROOT_DIR/../xwa-sdk/bindings/python}"
XWA_SDK_GIT="xwa-sdk @ git+https://github.com/xwebanalysis/xwa-sdk.git#subdirectory=bindings/python"
UV_BIN="${UV_BIN:-$HOME/.local/bin/uv}"
NODE_DIR="${MISE_NODE_DIR:-$HOME/.local/share/mise/installs/node/24/bin}"

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: ./kabuki.sh [local|docker] [backend|frontend|all]

Modes:
  local    (default) Native backend on :$BACKEND_PORT (SQLite) + frontend on :$FRONTEND_PORT
  docker   Full stack with Docker Compose (PostgreSQL 17) on the same ports

Legacy aliases: --sqlite, --native, --fast  ->  local
EOF
    exit "${1:-0}"
}

ensure_node() {
    if [ -d "$NODE_DIR" ]; then
        export PATH="$NODE_DIR:$PATH"
    fi
    if ! command -v node >/dev/null 2>&1; then
        echo -e "${RED}node not found. Install Node 24 (mise) or add it to PATH.${NC}" >&2
        exit 1
    fi
    local major
    major="$(node -p 'process.versions.node.split(".")[0]')"
    if [ "$major" -lt 24 ]; then
        echo -e "${YELLOW}warning: Node $major detected; Angular 22 requires Node 24.${NC}" >&2
    fi
}

find_compose() {
    if docker compose version &>/dev/null; then
        COMPOSE="docker compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE="docker-compose"
    else
        echo -e "${RED}Docker Compose not found. Install Docker or use local mode.${NC}"
        exit 1
    fi
}

create_venv() {
    cd "$ROOT_DIR/backend"
    if [ ! -x .venv/bin/python ]; then
        if [ -x "$UV_BIN" ]; then
            echo -e "${CYAN}Creating Python 3.13 venv with uv...${NC}"
            "$UV_BIN" venv --python 3.13 --seed .venv
        else
            echo -e "${YELLOW}uv not found, falling back to python3 -m venv${NC}"
            python3 -m venv .venv
        fi
    fi
}

pip_install() {
    if [ -x "$UV_BIN" ]; then
        "$UV_BIN" pip install --python "$ROOT_DIR/backend/.venv/bin/python" "$@"
    else
        "$ROOT_DIR/backend/.venv/bin/pip" install "$@"
    fi
}

install_backend_deps() {
    create_venv
    cd "$ROOT_DIR/backend"
    echo -e "${CYAN}Installing backend dependencies (dev included)...${NC}"
    pip_install -r requirements-dev.txt
    if [ -d "$XWA_SDK_LOCAL" ]; then
        echo -e "${CYAN}Installing xwa-sdk local editable: $XWA_SDK_LOCAL${NC}"
        pip_install -e "$XWA_SDK_LOCAL"
    else
        echo -e "${YELLOW}xwa-sdk sibling repo not found; installing from git fallback${NC}"
        pip_install "$XWA_SDK_GIT"
    fi
}

run_local_backend() {
    install_backend_deps
    cd "$ROOT_DIR/backend"
    export DB_DRIVER=sqlite
    export DB_PATH
    echo -e "${CYAN}Backend:  http://localhost:$BACKEND_PORT  (SQLite: $DB_PATH)${NC}"
    echo -e "${CYAN}API docs: http://localhost:$BACKEND_PORT/docs${NC}"
    exec .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port "$BACKEND_PORT" --reload
}

wait_for_backend() {
    local url="http://127.0.0.1:$BACKEND_PORT/api/health"
    for _ in $(seq 1 60); do
        if curl -s -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo -e "${RED}Backend did not answer at $url${NC}" >&2
    return 1
}

run_local_frontend() {
    ensure_node
    cd "$ROOT_DIR/frontend"
    if [ ! -d node_modules ]; then
        echo -e "${CYAN}Installing frontend dependencies...${NC}"
        npm ci || npm install
    fi
    echo -e "${CYAN}Frontend: http://localhost:$FRONTEND_PORT${NC}"
    exec npm start
}

run_local() {
    case "${1:-all}" in
        backend)
            run_local_backend
            ;;
        frontend)
            run_local_frontend
            ;;
        all)
            run_local_backend &
            BACKEND_PID=$!
            trap 'kill "$BACKEND_PID" 2>/dev/null || true' EXIT INT TERM
            wait_for_backend
            run_local_frontend
            ;;
        *)
            usage 1
            ;;
    esac
}

run_docker() {
    find_compose
    case "${2:-all}" in
        backend)
            $COMPOSE -f "$ROOT_DIR/docker-compose.yml" up --build backend
            ;;
        frontend)
            $COMPOSE -f "$ROOT_DIR/docker-compose.yml" up --build frontend
            ;;
        all)
            $COMPOSE -f "$ROOT_DIR/docker-compose.yml" up --build
            ;;
        *)
            usage 1
            ;;
    esac
}

MODE="${1:-local}"
COMPONENT="${2:-all}"

case "$MODE" in
    docker)
        run_docker "$MODE" "$COMPONENT"
        ;;
    local | --sqlite | --native | --fast)
        run_local "$COMPONENT"
        ;;
    backend | frontend | all)
        run_local "$MODE"
        ;;
    -h | --help)
        usage 0
        ;;
    *)
        usage 1
        ;;
esac

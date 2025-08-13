#!/usr/bin/env bash

# DevCoin launcher: builds and starts the Node (Rust) and Oracle (Go),
# optionally the Frontend (Vite). Supports stop/status/clean.
# Usage:
#   ./start.sh               # start node + oracle
#   ./start.sh --frontend    # start node + oracle + frontend
#   ./start.sh stop          # stop all
#   ./start.sh status        # show status
#   ./start.sh restart       # restart services
#   ./start.sh clean         # stop and remove data/logs/pids/binaries, cargo clean

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT_DIR/logs"
PID_DIR="$ROOT_DIR/.pids"
BIN_DIR="$ROOT_DIR/bin"
DATA_DIR_DEFAULT="$ROOT_DIR/.devcoin-data"

# Load environment from .env if present (auto-export)
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ROOT_DIR/.env"
  set +a
fi

# Defaults (can be overridden via environment before calling this script)
: "${DEVCOIN_ADDR:=127.0.0.1:8080}"
: "${DEVCOIN_DATA_DIR:=$DATA_DIR_DEFAULT}"
: "${DEVCOIN_AUTHORITIES:=authority1}"
: "${ORACLE_ADDR:=:8090}"
: "${BLOCKCHAIN_API:=http://127.0.0.1:8080}"
: "${ORACLE_PROPOSER:=authority1}"

mkdir -p "$LOG_DIR" "$PID_DIR" "$BIN_DIR" "$DEVCOIN_DATA_DIR"

log() { printf "[devcoin] %s\n" "$*"; }
warn() { printf "[devcoin][warn] %s\n" "$*" 1>&2; }
err() { printf "[devcoin][err] %s\n" "$*" 1>&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

is_running() { local pid="$1"; [[ -n "$pid" && -e "/proc/$pid" ]]; }

write_pid() { echo "$2" > "$PID_DIR/$1.pid"; }

read_pid() { local f="$PID_DIR/$1.pid"; [[ -f "$f" ]] && cat "$f" || true; }

rm_pid() { rm -f "$PID_DIR/$1.pid"; }

start_node() {
  need_cmd cargo
  log "Building devcoin node (Rust)…"
  cargo build --manifest-path "$ROOT_DIR/src/blockchain-node/Cargo.toml" -q
  local bin="$ROOT_DIR/src/blockchain-node/target/debug/devcoin-node"
  if [[ ! -x "$bin" ]]; then err "Node binary not found at $bin"; exit 1; fi

  local node_pid
  node_pid="$(read_pid node)"
  if is_running "$node_pid"; then
    log "Node already running (pid $node_pid)"
    return 0
  fi

  log "Starting node on $DEVCOIN_ADDR… (logs: $LOG_DIR/node.log)"
  (
    cd "$ROOT_DIR/src/blockchain-node"
    DEVCOIN_ADDR="$DEVCOIN_ADDR" \
    DEVCOIN_DATA_DIR="$DEVCOIN_DATA_DIR" \
    DEVCOIN_AUTHORITIES="$DEVCOIN_AUTHORITIES" \
    DEVCOIN_MINT_TOKEN="${DEVCOIN_MINT_TOKEN:-}" \
    DEVCOIN_AUTHORITIES_FILE="${DEVCOIN_AUTHORITIES_FILE:-}" \
    DEVCOIN_AUTHORITIES_KEYS="${DEVCOIN_AUTHORITIES_KEYS:-}" \
    DEVCOIN_REQUIRE_AUTHORITIES="${DEVCOIN_REQUIRE_AUTHORITIES:-}" \
    DEVCOIN_REQUIRE_SIGS="${DEVCOIN_REQUIRE_SIGS:-}" \
    "$bin" >> "$LOG_DIR/node.log" 2>&1 &
    write_pid node "$!"
  )

  # Wait for health endpoint
  need_cmd curl
  local url="http://$DEVCOIN_ADDR/health"
  for i in {1..60}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "Node is up at $url"
      return 0
    fi
    sleep 0.5
  done
  warn "Node did not become healthy in time; check $LOG_DIR/node.log"
}

start_oracle() {
  need_cmd go

  # Default webhook secret for local dev (override in env!)
  : "${GITHUB_WEBHOOK_SECRET:=dev-secret}"
  : "${REPO_WHITELIST:=}"
  # Reuse node token if provided
  : "${ORACLE_NODE_TOKEN:=${DEVCOIN_MINT_TOKEN:-}}"

  log "Building oracle (Go)…"
  (
    cd "$ROOT_DIR/src/contrib-oracle"
    go build -o "$BIN_DIR/devcoin-oracle" ./cmd/oracle
  )

  local oracle_pid
  oracle_pid="$(read_pid oracle)"
  if is_running "$oracle_pid"; then
    log "Oracle already running (pid $oracle_pid)"
    return 0
  fi

  log "Starting oracle on $ORACLE_ADDR… (logs: $LOG_DIR/oracle.log)"
  (
    cd "$ROOT_DIR"
    ORACLE_ADDR="$ORACLE_ADDR" \
    GITHUB_WEBHOOK_SECRET="$GITHUB_WEBHOOK_SECRET" \
    BLOCKCHAIN_API="$BLOCKCHAIN_API" \
    REPO_WHITELIST="$REPO_WHITELIST" \
    ORACLE_NODE_TOKEN="$ORACLE_NODE_TOKEN" \
    ORACLE_PROPOSER="$ORACLE_PROPOSER" \
    ORACLE_ED25519_PRIVKEY="${ORACLE_ED25519_PRIVKEY:-}" \
    ORACLE_ED25519_PRIVKEY_FILE="${ORACLE_ED25519_PRIVKEY_FILE:-}" \
    "$BIN_DIR/devcoin-oracle" >> "$LOG_DIR/oracle.log" 2>&1 &
    write_pid oracle "$!"
  )

  # Wait for health
  need_cmd curl
  local url
  # Convert :8090 to 127.0.0.1:8090 for health checks
  if [[ "$ORACLE_ADDR" == :* ]]; then
    url="http://127.0.0.1${ORACLE_ADDR}/healthz"
  else
    url="http://$ORACLE_ADDR/healthz"
  fi
  for i in {1..60}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "Oracle is up at $url"
      return 0
    fi
    sleep 0.5
  done
  warn "Oracle did not become healthy in time; check $LOG_DIR/oracle.log"
}

start_frontend() {
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm not found; skipping frontend"
    return 0
  fi
  local fe_pid
  fe_pid="$(read_pid frontend)"
  if is_running "$fe_pid"; then
    log "Frontend already running (pid $fe_pid)"
    return 0
  fi
  log "Starting frontend dev server… (logs: $LOG_DIR/frontend.log)"
  (
    cd "$ROOT_DIR/src/frontend"
    # Install deps if node_modules missing
    if [[ ! -d node_modules ]]; then npm ci || npm install; fi
    npm run dev >> "$LOG_DIR/frontend.log" 2>&1 &
    write_pid frontend "$!"
  )
  log "Frontend started (default: http://127.0.0.1:5173)"
}

stop_service() {
  local name="$1"
  local pid
  pid="$(read_pid "$name")"
  if [[ -n "$pid" ]]; then
    if is_running "$pid"; then
      log "Stopping $name (pid $pid)…"
      kill "$pid" || true
      # Graceful wait
      for i in {1..20}; do
        is_running "$pid" || break
        sleep 0.25
      done
      # Force kill if still alive
      if is_running "$pid"; then
        warn "$name (pid $pid) still running; killing -9"
        kill -9 "$pid" || true
      fi
    fi
    rm_pid "$name"
  else
    log "$name not running"
  fi
}

stop_all() {
  stop_service frontend || true
  stop_service oracle || true
  stop_service node || true
}

status() {
  for svc in node oracle frontend; do
    local pid
    pid="$(read_pid "$svc")"
    if [[ -n "$pid" && -e "/proc/$pid" ]]; then
      echo "$svc: running (pid $pid)"
    else
      echo "$svc: stopped"
    fi
  done
}

clean() {
  stop_all || true
  log "Cleaning data/logs/pids/bin…"
  rm -rf "$DEVCOIN_DATA_DIR" "$LOG_DIR" "$PID_DIR" "$BIN_DIR"
  mkdir -p "$LOG_DIR" "$PID_DIR" "$BIN_DIR"
  if command -v cargo >/dev/null 2>&1; then
    log "cargo clean (node)…"
    (cd "$ROOT_DIR/src/blockchain-node" && cargo clean -q) || true
  fi
  # Optionally clean frontend build artifacts
  rm -rf "$ROOT_DIR/src/frontend/dist" || true
  log "Clean complete."
}

main() {
  local do_frontend=false
  local cmd="start"
  for arg in "$@"; do
    case "$arg" in
      --frontend) do_frontend=true ;;
      start|stop|restart|status|clean) cmd="$arg" ;;
      *) ;;
    esac
  done

  case "$cmd" in
    start)
      start_node
      start_oracle
      if [[ "$do_frontend" == true ]]; then start_frontend; fi
      ;;
    stop)
      stop_all ;;
    restart)
      stop_all
      start_node
      start_oracle
      if [[ "$do_frontend" == true ]]; then start_frontend; fi
      ;;
    status)
      status ;;
    clean)
      clean ;;
  esac
}

main "$@"

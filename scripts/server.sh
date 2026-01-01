#!/usr/bin/env bash
# Lifecycle for the sui-gen apps' dev servers.
#
#   bash scripts/server.sh <app> <action>
#
# apps    : web | tutorial | all
# actions : start | stop | restart | status | open | logs | tail
#
# State is in $STATE_DIR (default ~/.local/state/sui-gen):
#   <app>.pid       PID of the running dev server
#   <app>.log       redirected stdout+stderr
#
# The script is safe to re-run: start is a no-op if alive on the expected port,
# stop is a no-op if nothing is running.
set -euo pipefail

STATE_DIR="${STATE_DIR:-$HOME/.local/state/sui-gen}"
mkdir -p "$STATE_DIR"

# App registry: name → port, pnpm filter
case "" in *) :;; esac  # appease set -u when iterating arrays

APP_WEB_PORT=3000
APP_WEB_FILTER="@sui-gen/web"

APP_TUTORIAL_PORT=3030
APP_TUTORIAL_FILTER="@sui-gen/tutorial"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

color() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
log()   { color "1;34" "[$1] $2"; }
ok()    { color "1;32" "[$1] $2"; }
warn()  { color "1;33" "[$1] $2"; }
die()   { color "1;31" "[$1] $2" >&2; exit 1; }

resolve_app() {
  case "$1" in
    web)      echo "$APP_WEB_PORT $APP_WEB_FILTER" ;;
    tutorial) echo "$APP_TUTORIAL_PORT $APP_TUTORIAL_FILTER" ;;
    *) die "$1" "Unknown app — use: web | tutorial | all" ;;
  esac
}

# ── port helpers ───────────────────────────────────────────────────────────
port_in_use() {
  lsof -ti tcp:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

http_ok() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://localhost:$1" | grep -qE '^(200|3..|404)$'
}

# ── lifecycle ──────────────────────────────────────────────────────────────
do_start() {
  local app="$1"
  read -r port filter <<<"$(resolve_app "$app")"
  local pidfile="$STATE_DIR/$app.pid"
  local logfile="$STATE_DIR/$app.log"

  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      warn "$app" "already running (pid=$pid, port=$port)"
      return 0
    fi
    rm -f "$pidfile"
  fi

  if port_in_use "$port"; then
    die "$app" "port $port is already in use by another process — \`lsof -i:$port\` to investigate"
  fi

  log "$app" "starting (port=$port, filter=$filter)"
  # nohup + disown so the dev server survives this shell. Keep stderr+stdout in logfile.
  (
    cd "$REPO_ROOT"
    nohup pnpm --filter "$filter" run dev >"$logfile" 2>&1 &
    echo $! >"$pidfile"
    disown 2>/dev/null || true
  )

  # Wait up to 30s for the port to start listening.
  for i in $(seq 1 30); do
    if port_in_use "$port"; then break; fi
    sleep 1
  done
  if port_in_use "$port"; then
    ok "$app" "ready → http://localhost:$port  (pid=$(cat "$pidfile"))"
  else
    warn "$app" "process started but port $port not listening yet — tail logs with: bash scripts/server.sh $app logs"
  fi
}

do_stop() {
  local app="$1"
  local pidfile="$STATE_DIR/$app.pid"
  if [ ! -f "$pidfile" ]; then
    warn "$app" "no PID file; nothing to stop"
    return 0
  fi
  local pid
  pid=$(cat "$pidfile")
  if [ -z "${pid:-}" ] || ! kill -0 "$pid" 2>/dev/null; then
    warn "$app" "pid $pid not alive; clearing stale PID file"
    rm -f "$pidfile"
    return 0
  fi
  log "$app" "stopping pid=$pid (+ child node processes)"
  # Next dev forks a child node; kill the whole process group.
  pkill -TERM -P "$pid" 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 10); do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.3
  done
  if kill -0 "$pid" 2>/dev/null; then
    warn "$app" "SIGTERM didn't take; sending SIGKILL"
    pkill -KILL -P "$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
  ok "$app" "stopped"
}

do_status() {
  local app="$1"
  read -r port filter <<<"$(resolve_app "$app")"
  local pidfile="$STATE_DIR/$app.pid"
  local pid_alive=no port_listening=no http_ok=no
  local pid=""

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then pid_alive=yes; fi
  fi
  if port_in_use "$port"; then port_listening=yes; fi
  if http_ok "$port"; then http_ok=yes; fi

  printf "%-9s port=%d  pid=%s  alive=%s  listening=%s  http_ok=%s\n" \
    "$app" "$port" "${pid:-—}" "$pid_alive" "$port_listening" "$http_ok"
}

do_open() {
  local app="$1"
  read -r port filter <<<"$(resolve_app "$app")"
  if ! port_in_use "$port"; then
    warn "$app" "not running; starting first"
    do_start "$app"
  fi
  log "$app" "opening http://localhost:$port"
  if [[ "$(uname)" == "Darwin" ]]; then
    open "http://localhost:$port"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:$port"
  else
    echo "open: http://localhost:$port"
  fi
}

do_logs() {
  local app="$1"
  local logfile="$STATE_DIR/$app.log"
  [ -f "$logfile" ] || die "$app" "no log file at $logfile"
  cat "$logfile"
}

do_tail() {
  local app="$1"
  local logfile="$STATE_DIR/$app.log"
  [ -f "$logfile" ] || die "$app" "no log file at $logfile"
  tail -f "$logfile"
}

# ── entry point ────────────────────────────────────────────────────────────
APP="${1:-}"
ACTION="${2:-}"
[ -n "$APP" ] && [ -n "$ACTION" ] || {
  cat <<EOF
Usage: bash scripts/server.sh <app> <action>

Apps:
  web         Next.js demo dApp        (port 3000)
  tutorial    Interactive tutorial      (port 3030)
  all         Apply to every app

Actions:
  start       Run the dev server in the background
  stop        Send SIGTERM (then SIGKILL after 3s)
  restart     stop && start
  status      PID alive? port listening? http responding?
  open        Open in your browser (starts if needed)
  logs        Print captured log
  tail        Follow log (Ctrl-C to exit)

Examples:
  bash scripts/server.sh tutorial start
  bash scripts/server.sh all status
  bash scripts/server.sh web open
EOF
  exit 1
}

apps_to_act_on=()
if [ "$APP" = "all" ]; then
  apps_to_act_on=(web tutorial)
else
  apps_to_act_on=("$APP")
fi

for a in "${apps_to_act_on[@]}"; do
  case "$ACTION" in
    start)   do_start "$a" ;;
    stop)    do_stop "$a" ;;
    restart) do_stop "$a";  do_start "$a" ;;
    status)  do_status "$a" ;;
    open)    do_open "$a" ;;
    logs)    do_logs "$a" ;;
    tail)    do_tail "$a" ;;
    *) die "$a" "Unknown action: $ACTION (start | stop | restart | status | open | logs | tail)" ;;
  esac
done

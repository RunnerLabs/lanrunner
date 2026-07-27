#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_BIN="$SCRIPT_DIR/lanrunner"
APP_URL="http://127.0.0.1:8080"
LOG_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/lanrunner/native-launch.log"

if [ ! -f "$APP_BIN" ]; then
  printf '%s\n' "The native Lanrunner binary was not found beside this launcher." >&2
  exit 1
fi

if [ ! -x "$APP_BIN" ]; then
  chmod +x "$APP_BIN" 2>/dev/null || {
    printf '%s\n' "Lanrunner is not executable. Run: chmod +x \"$APP_BIN\"" >&2
    exit 1
  }
fi

mkdir -p "$(dirname -- "$LOG_FILE")"
nohup "$APP_BIN" -no-browser "$@" >>"$LOG_FILE" 2>&1 &
APP_PID=$!

attempt=0
ready=0
while [ "$attempt" -lt 50 ]; do
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    printf '%s\n' "Lanrunner stopped before its interface became ready." >&2
    printf '%s\n' "Launch log: $LOG_FILE" >&2
    tail -n 20 "$LOG_FILE" 2>/dev/null >&2
    exit 1
  fi

  if command -v curl >/dev/null 2>&1; then
    if curl --silent --fail --max-time 1 "$APP_URL/" >/dev/null 2>&1; then
      ready=1
      break
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget --quiet --timeout=1 --spider "$APP_URL/" >/dev/null 2>&1; then
      ready=1
      break
    fi
  else
    sleep 2
    ready=1
    break
  fi

  attempt=$((attempt + 1))
  sleep 0.2
done

if [ "$ready" -ne 1 ]; then
  printf '%s\n' "Lanrunner did not become ready at $APP_URL." >&2
  printf '%s\n' "Launch log: $LOG_FILE" >&2
  tail -n 20 "$LOG_FILE" 2>/dev/null >&2
  exit 1
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$APP_URL" >/dev/null 2>&1 &
elif command -v gio >/dev/null 2>&1; then
  gio open "$APP_URL" >/dev/null 2>&1 &
else
  printf '%s\n' "Lanrunner is running. Open $APP_URL in your browser."
fi

printf '%s\n' "Lanrunner is running natively (PID $APP_PID)."
printf '%s\n' "Use EXIT APP in the page to stop it."
printf '%s\n' "Launch log: $LOG_FILE"

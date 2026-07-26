#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_URL="http://127.0.0.1:8080"
LOG_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/lanrunner/wine-launch.log"

if [ -n "${LANRUNNER_WINE_EXE:-}" ]; then
  APP_EXE="$LANRUNNER_WINE_EXE"
elif [ "${WINEARCH:-}" = "win32" ]; then
  APP_EXE="$SCRIPT_DIR/Lanrunner-x86.exe"
else
  APP_EXE="$SCRIPT_DIR/Lanrunner-x64.exe"
fi

if ! command -v wine >/dev/null 2>&1; then
  printf '%s\n' "Wine was not found. Install Wine, then run this launcher again." >&2
  exit 1
fi

if [ ! -f "$APP_EXE" ]; then
  printf '%s\n' "The selected Lanrunner Windows binary was not found: $APP_EXE" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$LOG_FILE")"
nohup wine "$APP_EXE" -no-browser "$@" >>"$LOG_FILE" 2>&1 &

attempt=0
while [ "$attempt" -lt 50 ]; do
  if command -v curl >/dev/null 2>&1; then
    if curl --silent --fail --max-time 1 "$APP_URL/" >/dev/null 2>&1; then
      break
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget --quiet --timeout=1 --spider "$APP_URL/" >/dev/null 2>&1; then
      break
    fi
  else
    sleep 2
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.2
done

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$APP_URL" >/dev/null 2>&1 &
  exit 0
fi

printf '%s\n' "Lanrunner is running. Open $APP_URL in your browser."
printf '%s\n' "Wine launch log: $LOG_FILE"

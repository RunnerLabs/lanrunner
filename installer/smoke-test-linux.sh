#!/bin/sh

set -eu

SOURCE_BIN=${1:-}
if [ -z "$SOURCE_BIN" ] || [ ! -f "$SOURCE_BIN" ]; then
  printf '%s\n' "usage: smoke-test-linux.sh /path/to/lanrunner-linux-amd64" >&2
  exit 2
fi

TEST_DIR=$(mktemp -d)
cleanup() {
  rm -rf -- "$TEST_DIR"
}
trap cleanup EXIT HUP INT TERM

cp "$SOURCE_BIN" "$TEST_DIR/lanrunner"
chmod +x "$TEST_DIR/lanrunner"

"$TEST_DIR/lanrunner" \
  -no-browser \
  -no-multicast \
  -ui 48081 \
  -disco 48101 \
  -idle 3s \
  -data "$TEST_DIR/data" \
  >"$TEST_DIR/run.log" 2>&1 &
APP_PID=$!

ready=0
attempt=0
while [ "$attempt" -lt 40 ]; do
  if curl -fsS http://127.0.0.1:48081/ | grep -qi Lanrunner; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.25
done

if [ "$ready" -ne 1 ]; then
  cat "$TEST_DIR/run.log" >&2
	exit 1
fi

if ! ss -ltn | grep -Eq '[:.]47101[[:space:]]'; then
  printf '%s\n' "fixed TCP messaging port 47101 is not listening" >&2
  cat "$TEST_DIR/run.log" >&2
  exit 1
fi

wait "$APP_PID"

if curl -fsS --max-time 1 http://127.0.0.1:48081/ >/dev/null 2>&1; then
  printf '%s\n' "port remained open after shutdown" >&2
	exit 1
fi

if ss -ltn | grep -Eq '[:.]47101[[:space:]]'; then
  printf '%s\n' "TCP messaging port 47101 remained open after shutdown" >&2
  exit 1
fi

printf '%s\n' "linux_amd64_ui=200"
printf '%s\n' "fixed_tcp_port=47101"
printf '%s\n' "idle_shutdown=true"
printf '%s\n' "port_released=true"

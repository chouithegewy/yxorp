#!/usr/bin/env bash
#
# End-to-end throughput comparison for the yxorp fast and uring engines using the
# dpbench tools (httpterm as the origin, h1load as the client).
#
# For each engine it runs two profiles:
#   - small: 64-byte keepalive responses  (RPS-bound)
#   - large: 1 MiB responses              (bandwidth-bound)
# and repeats the large profile with runtime.zero_copy = false so the buffered
# fallback can be compared against the splice / fixed-buffer path.
#
# Requires: dpbench/bin/httpterm and dpbench/bin/h1load (built via dpbench).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTPTERM="$ROOT/dpbench/bin/httpterm"
H1LOAD="$ROOT/dpbench/bin/h1load"
BIN="$ROOT/target/release/yxorp"
WORK="$(mktemp -d)"
DURATION="${DURATION:-5}"
CONNS="${CONNS:-50}"

SMALL_PORT=9101
LARGE_PORT=9102
PROXY_PORT=18080

for tool in "$HTTPTERM" "$H1LOAD"; do
    if [[ ! -x "$tool" ]]; then
        echo "missing dpbench tool: $tool (build dpbench first)" >&2
        exit 1
    fi
done

cleanup() {
    [[ -n "${HTTPTERM_PID:-}" ]] && kill "$HTTPTERM_PID" 2>/dev/null || true
    [[ -n "${YXORP_PID:-}" ]] && kill "$YXORP_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building release binary"
(cd "$ROOT" && cargo build --release --quiet)

cat >"$WORK/httpterm.cfg" <<EOF
global
	maxconn 30000
listen small 127.0.0.1:$SMALL_PORT
	maxconn 30000
	object weight 1 name s code 200 size 64
	clitimeout 10000
listen large 127.0.0.1:$LARGE_PORT
	maxconn 30000
	object weight 1 name l code 200 size 1048576
	clitimeout 10000
EOF

echo "==> starting httpterm origin"
"$HTTPTERM" -f "$WORK/httpterm.cfg" -D -q &
HTTPTERM_PID=$!
sleep 1

write_cfg() {
    local engine="$1" upstream_port="$2" zero_copy="$3"
    cat >"$WORK/yxorp.toml" <<EOF
[runtime]
zero_copy = $zero_copy

[[listeners]]
name = "bench"
bind = "127.0.0.1:$PROXY_PORT"
protocols = ["h1"]
http1_engine = "$engine"

[[routes]]
name = "root"
host = "*"
path_prefix = "/"
upstream_pool = "web"

[upstream_pools.web]
[[upstream_pools.web.upstreams]]
name = "web"
url = "http://127.0.0.1:$upstream_port"
protocol = "h1"
EOF
}

wait_for_port() {
    local port="$1" tries=0
    until curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; do
        tries=$((tries + 1))
        [[ $tries -gt 50 ]] && { echo "proxy did not come up on $port" >&2; return 1; }
        sleep 0.1
    done
}

run_case() {
    local engine="$1" upstream_port="$2" zero_copy="$3" label="$4"
    write_cfg "$engine" "$upstream_port" "$zero_copy"
    "$BIN" serve --config "$WORK/yxorp.toml" >/dev/null 2>&1 &
    YXORP_PID=$!
    wait_for_port "$PROXY_PORT"
    echo "---- $label (engine=$engine, zero_copy=$zero_copy) ----"
    "$H1LOAD" -d "$DURATION" -c "$CONNS" "http://127.0.0.1:$PROXY_PORT/" 2>&1 |
        grep -E "time +conns|^ *[0-9]" || true
    kill "$YXORP_PID" 2>/dev/null || true
    wait "$YXORP_PID" 2>/dev/null || true
    YXORP_PID=""
    echo
}

for engine in fast uring; do
    run_case "$engine" "$SMALL_PORT" true  "small 64B  RPS"
    run_case "$engine" "$LARGE_PORT" true  "large 1MiB zero-copy"
    run_case "$engine" "$LARGE_PORT" false "large 1MiB fallback"
done

echo "==> done"

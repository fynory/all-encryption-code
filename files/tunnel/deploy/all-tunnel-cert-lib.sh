# Shared by all-tunnel-cert-hook and all-tunnel-cert-check (installed next to them in /usr/local/sbin). Sourced, never run.
#
# Everything the node's certificate scripts need comes from the node's own environment file (the one systemd reads), so there is one place that says where the
# certificate is and what the node is called:
#   TUNNEL_NODE_HOST   the node's own public name         TUNNEL_CERT_FILE / TUNNEL_KEY_FILE   where the node reads its certificate and key
#   TUNNEL_METRICS_ADDR  the loopback address of /metrics (default 127.0.0.1:9101)
# Overrides for tests: ALL_TUNNEL_ENV (the file), ALL_TUNNEL_UNIT (the unit to reload), ALL_TUNNEL_LOGGER (the logger command).

ALL_TUNNEL_ENV="${ALL_TUNNEL_ENV:-/etc/all-tunnel/env}"
ALL_TUNNEL_UNIT="${ALL_TUNNEL_UNIT:-all-tunnel}"

env_value() {  # env_value KEY [DEFAULT]: the last KEY=value line of the environment file (no quotes, no expansion: it is a systemd EnvironmentFile)
  value=$(sed -n "s/^$1=//p" "$ALL_TUNNEL_ENV" 2>/dev/null | tail -n 1)
  if [ -n "$value" ]; then printf '%s\n' "$value"; else printf '%s\n' "${2:-}"; fi
}

say() {  # say PRIORITY MESSAGE: to the journal when logger exists, always to stderr (what systemd and certbot capture)
  printf 'all-tunnel-cert: %s\n' "$2" >&2
  if command -v "${ALL_TUNNEL_LOGGER:-logger}" >/dev/null 2>&1; then "${ALL_TUNNEL_LOGGER:-logger}" -p "daemon.$1" -t all-tunnel-cert "$2" || true; fi
}

die() { say crit "$1"; exit 1; }

# not_after_epoch FILE: the end of the certificate in Unix seconds (GNU date on the node, BSD date where a developer runs the tests)
not_after_epoch() {
  text=$(openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//')
  date -u -d "$text" +%s 2>/dev/null || date -u -j -f '%b %e %H:%M:%S %Y %Z' "$text" +%s 2>/dev/null || return 1
}

# metric NAME: one value of the node's loopback /metrics, empty when it cannot be read
metric() {
  addr=$(env_value TUNNEL_METRICS_ADDR 127.0.0.1:9101)
  curl -fsS --max-time 5 "http://$addr/metrics" 2>/dev/null | sed -n "s/^$1 //p" | head -n 1
}

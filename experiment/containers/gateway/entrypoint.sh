#!/usr/bin/env bash
# Egress-gateway entrypoint. Two jobs:
#   1. DNAT the literal cloud-metadata IP (169.254.169.254:80) to the in-network
#      mock-metadata stub, so attack cases that hit the real link-local address
#      land on our harmless decoy instead of failing/leaking. (Using 169.254/16
#      as a real Docker subnet is non-standard and the daemon may reject it, so
#      we redirect at the gateway instead of addressing the stub there.)
#   2. Render squid.conf from the template (substituting the ALLOW_DOMAIN
#      allowlist) and run Squid in the foreground as the proxy for live-net.
#
# This container holds NET_ADMIN (for iptables); the agent container does not.
set -euo pipefail

ALLOW_DOMAIN="${ALLOW_DOMAIN:?ALLOW_DOMAIN must be set (the model API domain to allowlist)}"
METADATA_HOST="${METADATA_HOST:-mock-metadata}"
METADATA_PORT="${METADATA_PORT:-80}"

echo "[gateway] allowlisting domain: ${ALLOW_DOMAIN}"
echo "[gateway] metadata stub: ${METADATA_HOST}:${METADATA_PORT}"

# Resolve the stub's current container IP for the DNAT target.
META_IP="$(getent hosts "${METADATA_HOST}" | awk '{print $1; exit}' || true)"
if [ -n "${META_IP}" ]; then
  echo "[gateway] DNAT 169.254.169.254:80 -> ${META_IP}:${METADATA_PORT}"
  # Redirect outbound traffic to the link-local metadata IP onto the stub.
  iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254 --dport 80 \
    -j DNAT --to-destination "${META_IP}:${METADATA_PORT}" || \
    echo "[gateway] WARN: could not install DNAT (need NET_ADMIN); metadata-IP redirect disabled"
  # Forwarded traffic (from the agent container routing through us) too.
  iptables -t nat -A PREROUTING -p tcp -d 169.254.169.254 --dport 80 \
    -j DNAT --to-destination "${META_IP}:${METADATA_PORT}" || true
  iptables -t nat -A POSTROUTING -j MASQUERADE || true
else
  echo "[gateway] WARN: mock-metadata not resolvable yet; metadata-IP DNAT skipped"
fi

# Render the allowlist into the live squid config.
export ALLOW_DOMAIN
envsubst '${ALLOW_DOMAIN}' < /etc/squid/squid.conf.template > /etc/squid/squid.conf
echo "[gateway] rendered squid.conf:"
sed 's/^/[gateway:squid.conf] /' /etc/squid/squid.conf

# Initialise the cache/log dirs squid expects, then run in foreground.
squid -N -z 2>/dev/null || true
echo "[gateway] starting squid on :3128"
exec squid -N -d1 -f /etc/squid/squid.conf

# syntax=docker/dockerfile:1
#
# Egress gateway image for live-net. A Squid forward proxy with a strict domain
# allowlist (gateway/squid.conf.template) PLUS a DNAT rule that redirects the
# literal cloud-metadata IP 169.254.169.254 to the in-network mock-metadata stub.
#
# This is the ONLY container that gets NET_ADMIN (for the iptables DNAT). The
# agent container stays --cap-drop ALL. The gateway both ENFORCES the allowlist
# and DETECTS exfil (its denied-CONNECT log is the signal).
#
# Pinned by digest like the agent images; Debian's squid is sufficient.
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:40b107342c492725bc7aacbe93a49945445191ae364184a6d24fedb28172f6f7
FROM ${DEBIAN_IMAGE}

# Build context is experiment/ (see docker-compose.yml); paths are relative to it.
# Corporate CA so apt over the proxy works during build.
COPY containers/corporate-ca.pem /usr/local/share/ca-certificates/corporate-ca.crt
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates squid iptables gettext-base curl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/squid && chown -R proxy:proxy /var/log/squid

COPY containers/gateway/squid.conf.template /etc/squid/squid.conf.template
COPY containers/gateway/entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod +x /usr/local/bin/gateway-entrypoint.sh

# Squid (3128) is the proxy port. Runs as root only long enough to install the
# DNAT rule, then Squid drops to the `proxy` user itself.
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]

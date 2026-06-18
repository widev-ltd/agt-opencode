# syntax=docker/dockerfile:1
#
# Benchmark agent image — OpenCode host (real `opencode` CLI + the packaged
# agt-opencode plugin). This is the in-container subject of the settings-vs-plugin
# benchmark (BENCHMARK-PLAN.md §Security/isolation, Phase 1).
#
# Hardening / fidelity goals:
#   - Base image pinned BY DIGEST (Phase-0 pin; mirrored into results/env.lock.json).
#   - opencode-ai and the plugin pinned by exact version / tgz so runs are reproducible.
#   - Corporate TLS interception is handled by TRUSTING the exported root CA via
#     NODE_EXTRA_CA_CERTS — every network op in this image is Node-based (npm,
#     opencode). We never disable TLS verification (that would permit MITM).
#   - Runs NON-ROOT. The compose file adds --cap-drop ALL, pids/mem limits, and a
#     read-only root FS; nothing secret is ever baked in — credentials arrive at
#     runtime via -e only (see docker-compose.yml).
#
# Base image digest is a build arg so Phase-0 / env.lock.json owns the single
# source of truth. Default is the digest verified on 2026-06-02.
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:7af03b14a13c8cdd38e45058fd957bf00a72bbe17feac43b1c15a689c029c732
FROM ${NODE_IMAGE}

# Pinned host + plugin versions (Phase-0 pins).
ARG OPENCODE_VERSION=1.15.13

# --- Corporate CA (TLS-intercepting proxy) -----------------------------------
# OpenCode/npm are Node processes, so NODE_EXTRA_CA_CERTS is sufficient here.
# Build context is experiment/ (see docker-compose.yml), so paths are relative
# to that; prepare-context.mjs stages these inputs.
COPY containers/corporate-ca.pem /usr/local/share/corporate-ca.pem
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/corporate-ca.pem
ENV npm_config_fund=false \
    npm_config_audit=false

# --- Real OpenCode CLI (pinned) ----------------------------------------------
RUN npm i -g "opencode-ai@${OPENCODE_VERSION}" && opencode --version

# --- The packaged plugin (pinned tgz, simulates npm distribution) ------------
COPY agt-opencode-0.1.0.tgz /tmp/agt-opencode.tgz
RUN npm i -g /tmp/agt-opencode.tgz && agt-opencode --version

# --- Non-root runtime --------------------------------------------------------
# The stock `node` user (uid 1000) already exists in the base image. The
# throwaway project tree and the decoy HOME are created/owned at compose time
# (volumes), so we only need to drop privilege here.
USER node
WORKDIR /home/node/project

# Default to an idle shell; the harness overrides CMD per scenario. We do NOT
# bake an ENTRYPOINT that runs the agent so `--network none` scenarios can run
# the exact same image with a different command.
CMD ["bash"]

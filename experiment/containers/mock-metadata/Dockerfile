# syntax=docker/dockerfile:1
#
# mock-metadata stub image — serves fake, canary-tagged cloud-metadata responses
# (AWS IMDS + GCP metadata) so SSRF/metadata attack cases have a harmless,
# reachable target. Pure Node, no deps. Non-root, digest-pinned.
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:7af03b14a13c8cdd38e45058fd957bf00a72bbe17feac43b1c15a689c029c732
FROM ${NODE_IMAGE}

# Build context is experiment/ (see docker-compose.yml); path is relative to it.
COPY containers/mock-metadata/server.mjs /opt/mock-metadata/server.mjs
USER node
# Listens on :80 inside the sealed network (no host port published).
CMD ["node", "/opt/mock-metadata/server.mjs"]

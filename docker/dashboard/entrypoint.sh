#!/bin/sh
# Drop from root to the host operator UID/GID, and add the docker.sock
# group so nested `docker run` works without a manual DOCKER_GID.
set -eu
UID_N="${RECON_HOST_UID:-1000}"
GID_N="${RECON_HOST_GID:-1000}"
GROUPS_N="${GID_N}"
if [ -S /var/run/docker.sock ]; then
    SOCK_GID="$(stat -c %g /var/run/docker.sock 2>/dev/null || true)"
    if [ -n "${SOCK_GID}" ] && [ "${SOCK_GID}" != "${GID_N}" ]; then
        GROUPS_N="${GID_N},${SOCK_GID}"
    fi
fi
if [ "$(id -u)" = "0" ] && command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid="${UID_N}" --regid="${GID_N}" --groups="${GROUPS_N}" -- "$@"
fi
exec "$@"

#!/bin/sh
# Make sure the mounted data directory is writable, then drop root.
set -e
# The agent needs root (it reads other processes' sockets and the NAT table).
if [ "$(id -u)" = "0" ] && [ "${TFV_RUN_AS_ROOT:-0}" != "1" ]; then
    mkdir -p "$TFV_DATA_DIR"
    chown -R tfv:tfv "$TFV_DATA_DIR"
    exec setpriv --reuid=tfv --regid=tfv --init-groups "$@"
fi
exec "$@"

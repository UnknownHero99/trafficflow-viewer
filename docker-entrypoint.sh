#!/bin/sh
# Make sure the mounted data directory is writable, then drop root.
set -e
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$TFV_DATA_DIR"
    chown -R tfv:tfv "$TFV_DATA_DIR"
    exec setpriv --reuid=tfv --regid=tfv --init-groups "$@"
fi
exec "$@"

#!/bin/sh
set -eu

DATA_DIR=/data

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  if ! chown -R portal:portal "$DATA_DIR"; then
    echo "warning: failed to chown $DATA_DIR to portal:portal" >&2
  fi
  exec su-exec portal "$@"
fi

exec "$@"

#!/bin/sh
set -eu

# Default timezone is UTC. datetime-local inputs are parsed with time.Local; without explicit TZ,
# Go uses UTC in the container, matching timestamps parsed from browser-local datetime-local values.
# Operators who want local time can override with TZ=Asia/Shanghai in .env. M2 fix: without this
# default, unset TZ behavior depended on host /etc/timezone and was unpredictable.
: "${TZ:=UTC}"
export TZ

DATA_DIR=/data

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  if ! chown -R portal:portal "$DATA_DIR"; then
    echo "warning: failed to chown $DATA_DIR to portal:portal" >&2
  fi
  exec su-exec portal "$@"
fi

exec "$@"

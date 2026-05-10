#!/bin/sh
set -eu

# 默认时区 UTC. 模板 datetime-local 输入用 time.Local 解析, 容器内不显式设
# TZ 时 Go 会用 UTC, 跟前端 datetime-local (浏览器本地时区) 解析后存的 UTC
# 时间戳一致. operator 想用本地时区 (例: admin 输入 18:00 想是北京 18:00)
# 在 .env 加 TZ=Asia/Shanghai 即可覆盖. M2 修复: 没这条默认值的话, 没设 TZ
# 的容器实际行为依赖宿主 /etc/timezone, 不可预测.
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

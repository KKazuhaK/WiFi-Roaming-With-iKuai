# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-alpine AS build
WORKDIR /src

# 先拉依赖, 这一层能被缓存 (go.mod / go.sum 不变时重新 build 很快).
# go.sum 必须一并拷入: 没它的话 go mod download 会按 go.mod 自由 resolve,
# 上游 mirror 被劫持时可能注入伪造版本; 有 go.sum 则按哈希校验, 拿到不一致直接 fail.
COPY go.mod go.sum ./
RUN go mod download

# 再拷源码
COPY . .

# 静态编译. CGO_ENABLED=0 保证二进制没 libc 依赖, 能跑在 scratch/distroless
# -trimpath: 去掉编译机路径, 减小信息泄漏
# -ldflags="-s -w": 去符号表, 缩小二进制
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/portal .

# ---------- runtime stage ----------
# 用 alpine 而非 scratch: 方便排查时 docker exec 进去看一眼.
# 如果追求极致安全可换成 gcr.io/distroless/static:nonroot
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata su-exec && \
    addgroup -S portal && adduser -S portal -G portal

WORKDIR /app
COPY --from=build /out/portal /app/portal
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN mkdir -p /data && chown portal:portal /data && chmod +x /app/docker-entrypoint.sh

VOLUME ["/data"]
# 容器里还是监听 28080, 和宿主机对齐, 少一层心智负担.
EXPOSE 28080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/portal"]

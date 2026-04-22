# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.22-alpine AS build
WORKDIR /src

# 先拉依赖, 这一层能被缓存 (go.mod 不变时重新 build 很快)
# 首次 build 会根据 go.mod 生成 go.sum; 之后可以把 go.sum 提交进 git 获得可复现构建.
COPY go.mod ./
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
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S portal && adduser -S portal -G portal

WORKDIR /app
COPY --from=build /out/portal /app/portal

USER portal
# 容器里还是监听 28080, 和宿主机对齐, 少一层心智负担.
EXPOSE 28080
ENTRYPOINT ["/app/portal"]

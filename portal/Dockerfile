# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-alpine AS build
WORKDIR /src

# Download dependencies first so this layer can be cached when go.mod/go.sum do not change.
# go.sum must be copied too; without it, go mod download resolves freely from go.mod, and a
# compromised upstream mirror could inject forged versions. go.sum enforces hash verification.
COPY go.mod go.sum ./
RUN go mod download

# Then copy source code.
COPY . .

# Static build. CGO_ENABLED=0 avoids libc dependency and works in scratch/distroless images.
# -trimpath removes build-machine paths to reduce information leakage.
# -ldflags="-s -w" strips symbols and reduces binary size.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/portal .

# ---------- runtime stage ----------
# Use alpine instead of scratch so docker exec can inspect the container during troubleshooting.
# For tighter security, switch to gcr.io/distroless/static:nonroot.
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata su-exec && \
    addgroup -S portal && adduser -S portal -G portal

WORKDIR /app
COPY --from=build /out/portal /app/portal
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN mkdir -p /data && chown portal:portal /data && chmod +x /app/docker-entrypoint.sh

VOLUME ["/data"]
# Keep 28080 inside the container to match the host port and reduce confusion.
EXPOSE 28080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/portal"]

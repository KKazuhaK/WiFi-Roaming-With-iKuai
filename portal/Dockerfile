# syntax=docker/dockerfile:1.6

# Build-from-source image, used by `docker compose up -d --build` (deployment
# mode A) and by the CI Dockerfile check.
#
# Releases do NOT go through this file. The release workflow compiles each
# architecture natively on the runner and feeds the binaries to
# Dockerfile.release, which avoids running a Go and npm toolchain under QEMU —
# an arm64 `npm ci` under emulation takes tens of minutes.

# ---------- web stage ----------
# The React bundle is built first so a change to the Go sources does not
# invalidate it, and vice versa.
FROM node:24-alpine AS web-builder
WORKDIR /web

# Manifests first: this layer is the expensive one and it only has to rerun when
# the dependency set actually changes.
COPY web-react/package.json web-react/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY web-react/ ./
# i18n/*.json lives outside web-react/ and is imported through the @i18n alias —
# the same files the Go binary embeds, so there is only ever one copy of a
# string. The relative path has to match what the alias resolves to (../i18n).
COPY i18n/ ../i18n/

# vite.config.ts writes to ../internal/web/dist, which does not exist in this
# stage's layout; redirect it to a local path and copy across stages instead.
RUN npx tsc -b && npx vite build --outDir /web/dist --emptyOutDir

# ---------- go stage ----------
FROM golang:1.25-alpine AS build
WORKDIR /src

# Download dependencies first so this layer can be cached when go.mod/go.sum do not change.
# go.sum must be copied too; without it, go mod download resolves freely from go.mod, and a
# compromised upstream mirror could inject forged versions. go.sum enforces hash verification.
COPY go.mod go.sum ./
RUN go mod download

# Then copy source code.
COPY . .

# Drop the bundle where //go:embed all:dist expects it. The directory is
# recreated rather than written into, so a stale file from the build context
# cannot survive into the binary.
RUN rm -rf internal/web/dist && mkdir -p internal/web/dist
COPY --from=web-builder /web/dist/ ./internal/web/dist/

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
#
# NOTE: keep this stage in sync with Dockerfile.release, which has to produce an
# identical runtime for the released images.
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

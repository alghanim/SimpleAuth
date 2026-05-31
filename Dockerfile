# =============================================================================
# SimpleAuth — Multi-stage Production Dockerfile
# =============================================================================
# Build:  docker build -t simpleauth .
# Run:    docker run -p 8080:8080 -v simpleauth-data:/data simpleauth
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build the Go binary
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache module downloads before copying full source
COPY go.mod go.sum ./
RUN go mod download

# Copy source and embedded UI assets
COPY . .

# Build args for version injection
ARG VERSION=docker
ARG BUILD_TIME=""

RUN if [ -z "$BUILD_TIME" ]; then BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ'); fi && \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
      -o /simpleauth \
      .

# ---------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ---------------------------------------------------------------------------
# Pinned to a supported Alpine release by digest. alpine:3.19 reached EOL
# (community support ended ~Nov 2025); 3.21 is supported into late 2026 and
# still receives security updates for krb5-libs/ca-certificates.
# Digest pin makes the base immutable; bump the tag+digest together on upgrade.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# OCI image labels
LABEL org.opencontainers.image.title="SimpleAuth" \
      org.opencontainers.image.description="Lightweight authentication server with LDAP, Kerberos/SPNEGO, and JWT support" \
      org.opencontainers.image.vendor="SimpleAuth" \
      org.opencontainers.image.source="https://github.com/bodaay/SimpleAuth" \
      org.opencontainers.image.licenses="MIT"

# Runtime dependencies:
#   ca-certificates  — TLS verification for outbound LDAP/HTTPS calls
#   krb5-libs        — Kerberos client libraries for SPNEGO authentication
#   tzdata           — timezone data for correct log timestamps
RUN apk add --no-cache \
      ca-certificates \
      krb5-libs \
      tzdata

# Create a non-root user for the service
RUN addgroup -S simpleauth && \
    adduser -S -G simpleauth -h /home/simpleauth -s /sbin/nologin simpleauth

# Persistent data directory (BoltDB, TLS certs, keytabs)
RUN mkdir -p /data && chown simpleauth:simpleauth /data
VOLUME /data

# Copy the compiled binary from builder
COPY --from=builder /simpleauth /usr/local/bin/simpleauth

# Default environment — override at runtime as needed
ENV AUTH_DATA_DIR=/data \
    AUTH_PORT=8080 \
    AUTH_HTTP_PORT="" \
    AUTH_HOSTNAME="" \
    AUTH_BASE_PATH=""

# Expose the HTTPS port (the app handles its own TLS)
EXPOSE 8080

# Health check: uses AUTH_BASE_PATH and AUTH_PORT env vars at runtime
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --spider -q http://localhost:${AUTH_PORT}${AUTH_BASE_PATH}/health || exit 1

# Run as non-root
USER simpleauth

ENTRYPOINT ["simpleauth"]

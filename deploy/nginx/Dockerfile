# =============================================================================
# SimpleAuth — Nginx Reverse Proxy
# =============================================================================
# Provides TLS termination and rate limiting in front of SimpleAuth.
#
# Build:  docker build -t simpleauth-nginx deploy/nginx/
#
# Uses the official UNPRIVILEGED nginx image: the master process runs as the
# non-root `nginx` user (UID 101), not root. It listens on 8080 (HTTP) and
# 8443 (HTTPS) inside the container; compose maps host 80/443 -> 8080/8443.
# Pinned by digest so the base is immutable; bump tag+digest together on upgrade.
# =============================================================================

FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0

# All file operations that touch root-owned paths must run before USER drops.
USER root

# Remove default config
RUN rm -f /etc/nginx/conf.d/default.conf

# Copy production config
COPY nginx.conf /etc/nginx/nginx.conf

# Create directories for SSL certs and ACME challenges, owned by the nginx user
# so the non-root master process can read certs and write challenge files.
RUN mkdir -p /etc/nginx/ssl /var/www/certbot \
    && chown -R nginx:nginx /etc/nginx/ssl /var/www/certbot

# Drop back to the unprivileged user the base image ships with.
USER nginx

# Non-privileged ports (host 80/443 are mapped to these by compose).
EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-check-certificate --spider -q https://localhost:8443/health || exit 1

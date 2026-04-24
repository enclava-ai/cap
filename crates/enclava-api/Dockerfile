# Build stage
FROM rust:1.88-alpine AS builder

# Install musl build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

# Set up working directory
WORKDIR /build

# Copy Cargo manifests and workspace crates
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build static binaries
RUN cargo build --release --bin enclava-api --bin kbs-resource-writer && \
    strip /build/target/release/enclava-api && \
    strip /build/target/release/kbs-resource-writer

# Runtime stage
FROM alpine:3.20

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1000 enclava && \
    adduser -D -u 1000 -G enclava enclava

# Copy binary from builder
COPY --from=builder /build/target/release/enclava-api /usr/local/bin/enclava-api
COPY --from=builder /build/target/release/kbs-resource-writer /usr/local/bin/kbs-resource-writer

# Set permissions
RUN chown enclava:enclava /usr/local/bin/enclava-api /usr/local/bin/kbs-resource-writer

# Switch to non-root user
USER enclava

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/health || exit 1

# Set default environment (override in deployment)
ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    BTCPAY_URL="http://btcpay:23001" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]

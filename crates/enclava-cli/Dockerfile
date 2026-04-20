# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev git

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build for musl (static binary)
RUN cargo build --release --bin enclava && \
    strip /build/target/release/enclava

FROM alpine:3.20

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]

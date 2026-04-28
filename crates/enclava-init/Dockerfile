FROM rust:1.88-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      clang \
      libclang-dev \
      libcryptsetup-dev \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p enclava-init

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      e2fsprogs \
      libcryptsetup12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/enclava-init /usr/local/bin/enclava-init

ENTRYPOINT ["/usr/local/bin/enclava-init"]

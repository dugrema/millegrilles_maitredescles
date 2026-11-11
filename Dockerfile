# Build stage
FROM nexus.maple.maceroc.com/docker_proxy/rust:1-trixie AS builder

# Arguments for proxies
ARG APT_PROXY
ARG CARGO_REGISTRY_URL

# Install build dependencies
# Install build dependencies
RUN if [ -n "$APT_PROXY" ]; then \
         echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/01proxy; \
    fi && \
    if [ -n "$CARGO_REGISTRY_URL" ]; then \
        mkdir -p .cargo && \
        echo -e "[registries.crates-io]\nreplace-with = \"nexus\"\n[registries.nexus]\nindex = \"$CARGO_REGISTRY_URL\"" > .cargo/config.toml.test; \
    fi && \
    apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy configuration files first for layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy project to pre-build dependencies
RUN mkdir src && \
    echo "fn main() {println!(\"dummy project\");}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code and build the actual application. Cargo tree lists dependency versions.
COPY . .
RUN touch src/main.rs && cargo tree && cargo build --release

# Runtime stage
FROM nexus.maple.maceroc.com/docker_proxy/debian:trixie-slim

ARG APT_PROXY
ENV APP_FOLDER=/usr/src/app \
    RUST_LOG=warn \
    MG_MQ_HOST=mq \
    MG_MONGO_HOST=mongo \
    CAFILE=/run/secrets/millegrille.cert.pem \
    KEYFILE=/run/secrets/key_cert.pem \
    MG_REDIS_URL=rediss://client_rust@redis:6379#insecure \
    MG_REDIS_PASSWORD_FILE=/run/secrets/passwd.redis.txt

# Install runtime dependencies
RUN if [ -n "$APT_PROXY" ]; then \
      echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/01proxy; \
    fi && \
    mkdir -p /var/opt/millegrilles/archives && chown 1000:1000 /var/opt/millegrilles/archives && \
    apt-get update && apt-get install -y ca-certificates libssl3 && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $APP_FOLDER

COPY --from=builder /app/target/release/millegrilles_maitredescles .

USER 1000:1000

VOLUME ["/var/opt/millegrilles/archives"]

CMD ["./millegrilles_maitredescles"]

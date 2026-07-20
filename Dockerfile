# Build stage
FROM rust:1-trixie AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
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

# Copy source code and build the actual application
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

ENV APP_FOLDER=/usr/src/app \
    RUST_LOG=warn \
    MG_MQ_HOST=mq \
    MG_MONGO_HOST=mongo \
    CAFILE=/run/secrets/millegrille.cert.pem \
    KEYFILE=/run/secrets/key.pem \
    CERTFILE=/run/secrets/cert.pem \
    MG_REDIS_URL=rediss://client_rust@redis:6379#insecure \
    MG_REDIS_PASSWORD_FILE=/run/secrets/passwd.redis.txt

# Install runtime dependencies
RUN mkdir -p /var/opt/millegrilles/archives && chown 1000:1000 /var/opt/millegrilles/archives && \
    apt-get update && apt-get install -y ca-certificates libssl3 && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $APP_FOLDER

COPY --from=builder /app/target/release/millegrilles_maitredescles .

USER 1000:1000

VOLUME ["/var/opt/millegrilles/archives"]

CMD ["./millegrilles_maitredescles"]

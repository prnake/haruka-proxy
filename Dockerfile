# Stage 1: Build
FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src
COPY models.json ./

# Build the actual binary
RUN touch src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl || cargo build --release

# Stage 2: Runtime
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/haruka_proxy /app/haruka_proxy
COPY --from=builder /app/models.json /app/models.json

# Create non-root user
RUN addgroup -g 1000 haruka && \
    adduser -u 1000 -G haruka -s /bin/sh -D haruka && \
    chown -R haruka:haruka /app

USER haruka

# Expose port
EXPOSE 30033

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:30033/ || exit 1

# Run
CMD ["/app/haruka_proxy"]


# Dockerfile-backend
FROM rust:1.76-slim

# Create a new empty shell project
RUN USER=root cargo new --bin sphyre-rust
WORKDIR /sphyre-rust

# Copy Cargo files
COPY Cargo.toml sphyre-rust/Cargo.toml

# Build dependencies first
RUN cargo build --release
RUN rm src/*.rs

# Copy source code
COPY . .

# Build the actual binary
RUN cargo build --release

# Run it
CMD ["./target/release/sphyre-rust"]
EXPOSE 8080

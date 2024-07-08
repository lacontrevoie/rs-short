FROM rust:1-bookworm AS builder

WORKDIR /run_dir

COPY . .

RUN cargo build --release --no-default-features --features postgres

FROM debian:bookworm-slim

RUN apt update \
    && apt -y install libpq5 \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /run_dir

# config.toml will be missing and needs to be mounted
COPY --from=builder /run_dir/target/release/rs-short /run_dir/lists.toml /run_dir/lang.toml /run_dir/assets/ ./

RUN adduser --disabled-password --gecos "" --no-create-home "unprivileged"

USER unprivileged

CMD ["/run_dir/rs-short"]

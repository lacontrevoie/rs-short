FROM rust:1-bookworm AS builder

WORKDIR /run_dir

COPY . .

RUN cargo build --release --no-default-features --features postgres

FROM debian:bookworm-slim

WORKDIR /run_dir

COPY --from=builder /run_dir/target/release/rs-short /run_dir/lists.toml ./

RUN adduser --disabled-password --gecos "" --no-create-home "unprivileged"

USER unprivileged

CMD ["/run_dir/rs-short"]

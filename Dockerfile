FROM rust:1.61-slim-buster AS build

COPY ./ /tmp/build

WORKDIR /tmp/build

RUN apt-get update -y && \
    apt-get install -y pkg-config libssl-dev && \ 
    cargo build --release

FROM registry.suse.com/bci/bci-micro:15.4

COPY --from=build /tmp/build/target/release/user-manifest user-manifest

CMD ["./user-manifest"]

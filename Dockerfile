# Build Stage
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang curl
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN ${HOME}/.cargo/bin/rustup default nightly
RUN ${HOME}/.cargo/bin/cargo install -f cargo-fuzz

## Add source code to the build stage.
ADD . /smithy-rs
WORKDIR /smithy-rs

RUN cd rust-runtime/aws-smithy-json/fuzz && ${HOME}/.cargo/bin/cargo fuzz build
RUN cd rust-runtime/aws-smithy-eventstream/fuzz && ${HOME}/.cargo/bin/cargo fuzz build
# RUN cd rust-runtime/aws-config/fuzz && ${HOME}/.cargo/bin/cargo fuzz build
RUN cd rust-runtime/aws-smithy-http/fuzz && ${HOME}/.cargo/bin/cargo fuzz build
RUN cd rust-runtime/aws-smithy-types/fuzz && ${HOME}/.cargo/bin/cargo fuzz build


# Package Stage
FROM ubuntu:20.04

COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/corrected_prelude_crc /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/mutated_headers /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/parse_date_time /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/parse_epoch_seconds /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/parse_http_date /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/prelude /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/raw_bytes /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/read_date_time /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/read_http_date /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/read_many_from_str /
COPY --from=builder smithy-rs/target/x86_64-unknown-linux-gnu/release/round_trip /


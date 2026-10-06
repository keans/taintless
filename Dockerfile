# Build:  docker build -t taintless .
# Run:    docker run --rm -v "$PWD:/src:ro" taintless --no-cache security .

FROM rust:1-slim AS build
# the tree-sitter grammars are compiled from C
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY examples ./examples
RUN cargo install --path . --locked --root /out

FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends graphviz \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/bin/taintless /usr/local/bin/taintless
# the project to scan is mounted at /src (read-only is fine); mount a volume at
# /cache and pass `--cache /cache/db.sqlite` to keep the cache out of the project
RUN mkdir -m 1777 /cache
WORKDIR /src
ENTRYPOINT ["taintless"]
CMD ["--help"]

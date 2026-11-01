# syntax=docker/dockerfile:1
# Pushharbor native relay (SQLite or PostgreSQL). Build: docker build -t pushharbor-native .
# Run:   docker run -p 8080:8080 -v pushharbor-data:/data \
#          -e PUSHHARBOR_ORIGIN=https://push.example.com \
#          -e PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE=/run/secrets/fcm.json \
#          -v ./service-account.json:/run/secrets/fcm.json:ro pushharbor-native
# Several instances / no persistent disk: -e PUSHHARBOR_DATABASE_URL=postgres://user:pass@host/db

FROM rust:1.98-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p pushharbor-native \
    && cp target/release/pushharbor-native /pushharbor-native \
    && mkdir /data

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=build /pushharbor-native /usr/local/bin/pushharbor-native
# SQLite lives on this volume; owned by the image's non-root user (65532).
COPY --from=build --chown=65532:65532 /data /data
ENV PUSHHARBOR_LISTEN=0.0.0.0:8080 \
    PUSHHARBOR_DATABASE_URL=sqlite:///data/pushharbor.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pushharbor-native"]

FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
# Built from the repository root (docker build -f server/Dockerfile .): the
# server imports the client core's pure packages through replace ../core. A
# core holding only those packages requires no module and has no go.sum, so the
# pattern matches it when it exists.
WORKDIR /src/server
COPY core/go.mod core/go.su[m] /src/core/
COPY server/go.mod server/go.sum /src/server/
# BuildKit cache mounts keep Go's module + build caches across builds on the
# same host, so an update recompiles only what changed (~seconds) instead of
# the whole server from scratch (minutes on a 1-vCPU VPS).
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY core /src/core
COPY server /src/server
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/hyperdrop-server .

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# The server runs as the fixed uid 10001 and holds only the capability to bind
# ports 80 and 443. /data is created owned by that user, so a new named volume
# is seeded with the same owner.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10001 hyperdrop \
 && adduser -S -u 10001 -G hyperdrop hyperdrop \
 && mkdir /data && chown hyperdrop:hyperdrop /data
COPY --from=build /out/hyperdrop-server /usr/local/bin/hyperdrop-server
RUN apk add --no-cache libcap \
 && setcap cap_net_bind_service=+ep /usr/local/bin/hyperdrop-server \
 && apk del libcap
COPY server/THIRD-PARTY-NOTICES.txt /usr/share/doc/hyperdrop-server/THIRD-PARTY-NOTICES.txt
VOLUME /data
EXPOSE 80 443
USER 10001:10001
ENTRYPOINT ["hyperdrop-server"]

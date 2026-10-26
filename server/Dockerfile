FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
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

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/hyperdrop-server /usr/local/bin/hyperdrop-server
COPY server/THIRD-PARTY-NOTICES.txt /usr/share/doc/hyperdrop-server/THIRD-PARTY-NOTICES.txt
VOLUME /data
EXPOSE 80 443
ENTRYPOINT ["hyperdrop-server"]

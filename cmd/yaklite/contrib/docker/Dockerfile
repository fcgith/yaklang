# yaklite for a NAS, a Raspberry Pi or any always-on Linux box.
# Build from the repository root:
#   docker build -f cmd/yaklite/contrib/docker/Dockerfile -t yaklite .
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /yaklite ./cmd/yaklite

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 -d /data yaklite && mkdir -p /data && chown yaklite /data
COPY --from=build /yaklite /usr/local/bin/yaklite
USER yaklite
ENV XDG_STATE_HOME=/data/state XDG_CONFIG_HOME=/data/config
VOLUME /data
ENTRYPOINT ["yaklite"]
CMD ["watch", "-t", "192.168.1.0/24", "--checks", "--every", "1h", "--listen", "127.0.0.1:9842"]

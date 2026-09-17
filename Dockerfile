# syntax=docker/dockerfile:1.7

FROM golang:1.26.6-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/xsync-server ./cmd/xsync-server

FROM scratch

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="xsync-server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=builder /out/xsync-server /xsync-server

USER 65532:65532
WORKDIR /data
VOLUME ["/data", "/etc/xsync"]
EXPOSE 2022 2121 9000 9443 30000-30100

ENTRYPOINT ["/xsync-server"]
CMD ["serve", "--config", "/etc/xsync/config.yaml"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/xsync-server", "healthcheck", "--url", "http://127.0.0.1:9090/metrics"]

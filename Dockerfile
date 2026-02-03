FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/wg-keeper-node ./cmd/server

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache \
      wireguard-tools iproute2 iptables ca-certificates \
  && update-ca-certificates
COPY --from=builder /out/wg-keeper-node /app/wg-keeper-node
COPY --chmod=0755 entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
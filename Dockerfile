ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-trixie AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
  -o /out/ac ./cmd/ac

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG SOURCE=https://github.com/Kubedoll-Heavy-Industries/agentcontainers

LABEL org.opencontainers.image.title="agentcontainers" \
  org.opencontainers.image.description="Immutable, reproducible, least-privilege runtime environments for AI agents" \
  org.opencontainers.image.licenses="MIT" \
  org.opencontainers.image.source=$SOURCE \
  org.opencontainers.image.version=$VERSION \
  org.opencontainers.image.revision=$COMMIT \
  org.opencontainers.image.created=$DATE

COPY --from=build /out/ac /ac
ENTRYPOINT ["/ac"]

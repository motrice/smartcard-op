# SPDX-FileCopyrightText: 2026 Motrice AB
#
# SPDX-License-Identifier: EUPL-1.2

# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/smartcard-op ./cmd/smartcard-op

FROM scratch AS export-binary
COPY --from=builder /out/smartcard-op /smartcard-op

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/smartcard-op /usr/local/bin/smartcard-op
# 8080 is the issuer listener, 8081 the card listener behind mTLS.
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/smartcard-op"]

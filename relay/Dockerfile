# syntax=docker/dockerfile:1

# Cross-compile on the build platform instead of emulating the target, since
# the relay is pure Go with no cgo.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/relay .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relay /relay
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/relay", "-healthcheck"]
ENTRYPOINT ["/relay"]

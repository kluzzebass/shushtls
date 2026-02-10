# Build stage: compile static binary from source.
# GOTOOLCHAIN=auto lets the toolchain from go.mod be used (e.g. 1.25.7).
FROM golang:1.23-alpine AS builder
WORKDIR /build

ENV GOTOOLCHAIN=auto
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /shushtls .

# Runtime stage: minimal image; state lives in a volume.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates

# State directory: CA and certs. Mount a volume here so data survives
# container restarts and image updates. If you don't, certs will be lost on update.
VOLUME ["/data/shushtls"]

EXPOSE 8080 8443

COPY --from=builder /shushtls /shushtls
ENTRYPOINT ["/shushtls"]
CMD ["-state-dir", "/data/shushtls", "-http-addr", "0.0.0.0:8080", "-https-addr", "0.0.0.0:8443"]

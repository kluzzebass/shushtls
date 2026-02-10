# ShushTLS — command runner recipes

# Default: list available recipes.
_default:
    just --list

# Build the binary.
build:
    go build -o shushtls .

# Build with version for release (e.g. just build-release 1.0.0).
build-release version:
    go build -ldflags "-X shushtls/internal/version.Version={{ version }}" -o shushtls .

# Run all tests.
test:
    go test -count=1 -timeout 60s ./...

# Run the server (dev mode).
run:
    go run .

# Remove build artifacts.
clean:
    rm -f shushtls

# Build Docker image (current arch only).
docker-build:
    docker build -t shushtls .

# Build multi-arch Docker image and push. Usage: just docker-build-multi ghcr.io/user/shushtls:v1
docker-build-multi tag:
    docker buildx build --platform linux/amd64,linux/arm64 -t {{ tag }} . --push

# ShushTLS — command runner recipes

# Build the binary.
build:
    go build -o shushtls .

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

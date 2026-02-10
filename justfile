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

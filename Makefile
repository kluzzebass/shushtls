.PHONY: build test clean

# Build the ShushTLS binary using vendored dependencies.
build:
	go build -mod=vendor -o shushtls .

# Run all tests.
test:
	go test -mod=vendor -count=1 -timeout 60s ./...

# Remove build artifacts.
clean:
	rm -f shushtls

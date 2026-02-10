.PHONY: build test clean

# Build the ShushTLS binary.
build:
	go build -o shushtls .

# Run all tests.
test:
	go test -count=1 -timeout 60s ./...

# Remove build artifacts.
clean:
	rm -f shushtls

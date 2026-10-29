all: cli

cli:
	@echo "Building CLI..."
	@mkdir -p dist
	go build -ldflags="-s -w" -o dist/cli ./cmd/cli

webserver:
	@echo "Building web server..."
	@mkdir -p dist
	go build -tags server -ldflags="-s -w" -o dist/webserver ./cmd/server

wasm:
	@echo "Building WASM..."
	@mkdir -p web
	GOOS=js GOARCH=wasm go build -tags wasm -ldflags="-s -w" -o web/main.wasm ./cmd/wasm

derive:
	@echo "Bundling JS address derivation..."
	bun build src/derive.js --outfile web/derive.js --format esm --minify
	@echo "Bundled: $$(ls -lh web/derive.js | awk '{print $$5}')"

pages: wasm derive
	@echo "Compressing WASM for deployment..."
	gzip -f web/main.wasm
	@echo "Compressed: $$(ls -lh web/main.wasm.gz | awk '{print $$5}')"

test:
	@echo "Running Go tests..."
	go test $$(go list ./... | grep -v /pkg/recovery)
	@echo "Running JS derive tests..."
	bun run src/derive.test.js
	@echo "Running JS decryption tests..."
	bun run src/aes_gcm.test.js

test-cgo:
	@echo "Running all Go tests (requires CGo + libgodkls)..."
	go test ./...

check:
	@echo "Checking code formatting..."
	go fmt ./...
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist/
	rm -f web/main.wasm web/main.wasm.gz web/derive.js

.PHONY: all cli webserver wasm derive pages test test-cgo check clean

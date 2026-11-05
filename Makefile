.PHONY: build test security

build:
	mkdir -p bin
	go build -o bin/router-agent ./cmd/router-agent

test:
	go test -race ./...
	go vet ./...

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

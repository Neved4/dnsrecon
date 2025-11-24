.POSIX:

.PHONY: all fmt vet test tidy build run clean

all: fmt vet test

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

tidy:
	go mod tidy

build:
	go build -o dnspeek ./cmd/dnspeek

run:
	go run ./cmd/dnspeek

clean:
	rm -f dnspeek

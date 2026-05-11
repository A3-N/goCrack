.PHONY: build clean install test

ifeq ($(OS),Windows_NT)
BINARY ?= goCrack.exe
else
BINARY ?= goCrack
endif

build:
	go build -o $(BINARY) .

test:
	go test ./...

install:
	go run ./cmd/gocrack-userbin

clean:
	go clean

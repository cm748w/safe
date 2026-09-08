.PHONY: build vet test run-server run-client up down clean

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

run-server:
	go run ./cmd/server

run-client:
	go run ./cmd/client -file data/input.json -server http://localhost:8080

up:
	docker compose up --build

down:
	docker compose down

clean:
	rm -rf bin

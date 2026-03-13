.PHONY: run tidy

run:
	go run ./cmd/server

tidy:
	go mod tidy
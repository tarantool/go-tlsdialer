.PHONY: test
test:
	@echo "Running tests"
	@go test ./... -count=1 -v

.PHONY: lint-deps
lint-deps:
	@echo "Installing lint deps"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

.PHONY: lint
lint: lint-deps
	@echo "Running go-linter"
	@go mod tidy
	@go mod vendor
	@golangci-lint run ./...

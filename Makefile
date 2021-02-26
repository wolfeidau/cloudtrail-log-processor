APPNAME := cloudtrail-log-processor
STAGE ?= dev
BRANCH ?= master

GOLANGCI_VERSION = 1.32.0

BIN_DIR ?= $(shell pwd)/bin

GIT_HASH := $(shell git rev-parse --short HEAD)

ci: clean lint test
.PHONY: ci

LDFLAGS := -ldflags="-s -w -X version=${GIT_HASH}"

$(BIN_DIR)/golangci-lint: $(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} $(BIN_DIR)/golangci-lint
$(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}:
	@curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@mv $(BIN_DIR)/golangci-lint $@

$(BIN_DIR)/mockgen:
	@go get -u github.com/golang/mock/mockgen
	@env GOBIN=$(BIN_DIR) GO111MODULE=on go install github.com/golang/mock/mockgen

clean:
	@echo "--- clean all the things"
	@rm -rf ./dist
.PHONY: clean

lint: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run
.PHONY: lint

lint-fix: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run --fix
.PHONY: lint-fix

test:
	@echo "--- test all the things"
	@go test -coverprofile=coverage.txt ./...
	@go tool cover -func=coverage.txt
.PHONY: test

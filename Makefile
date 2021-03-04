APPNAME := cloudtrail-log-processor
STAGE ?= dev
BRANCH ?= master

GOLANGCI_VERSION = 1.32.0

BIN_DIR ?= $(shell pwd)/bin

GIT_HASH := $(shell git rev-parse --short HEAD)

default: clean build archive deploy
.PHONY: default

ci: clean lint test
.PHONY: ci

LDFLAGS := -ldflags="-s -w -X main.version=${GIT_HASH}"

$(BIN_DIR)/golangci-lint: $(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} $(BIN_DIR)/golangci-lint
$(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}:
	@curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@mv $(BIN_DIR)/golangci-lint $@

$(BIN_DIR)/mockgen:
	@go get -u github.com/golang/mock/mockgen
	@env GOBIN=$(BIN_DIR) GO111MODULE=on go install github.com/golang/mock/mockgen

mocks: $(BIN_DIR)/mockgen
	@echo "--- build all the mocks"
	@bin/mockgen -destination=mocks/ssmcache.go -package=mocks github.com/wolfeidau/ssmcache Cache
.PHONY: mocks

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

build:
	@echo "--- build all the things"
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -trimpath -o dist ./cmd/...
.PHONY: build

archive:
	@echo "--- build an archive"
	@cd dist && zip -X -9 -r ./handler.zip *-lambda
.PHONY: archive

deploy:
	@echo "--- deploy stack $(APPNAME)-$(STAGE)-$(BRANCH)"
	@sam deploy \
		--no-fail-on-empty-changeset \
		--template-file sam/app/cloudtrail_processor.yaml \
		--capabilities CAPABILITY_IAM \
		--s3-bucket $(shell aws ssm get-parameter --name "/config/$(STAGE)/deploy_bucket" --query 'Parameter.Value' --output text) \
		--s3-prefix sam/$(GIT_HASH) \
		--tags "environment=$(STAGE)" "branch=$(BRANCH)" "service=$(APPNAME)" \
		--stack-name $(APPNAME)-$(STAGE)-$(BRANCH) \
		--parameter-overrides AppName=$(APPNAME) Stage=$(STAGE) Branch=$(BRANCH) \
			CloudtrailBucketName=$(shell aws ssm get-parameter --name "/config/$(STAGE)/cloudtrail_bucket" --query 'Parameter.Value' --output text) \
			CloudtrailTopicArn=$(shell aws ssm get-parameter --name "/config/$(STAGE)/cloudtrail_topic_arn" --query 'Parameter.Value' --output text)
.PHONY: deploy
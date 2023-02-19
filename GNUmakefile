# PROVIDER_DIR is used instead of PWD since docker volume commands can be dangerous to run in $HOME.
# This ensures docker volumes are mounted from within provider directory instead.
PROVIDER_DIR := $(abspath $(lastword $(dir $(MAKEFILE_LIST))))
TEST         := "$(PROVIDER_DIR)/aquasec"
HOSTNAME	 := github.com
NAMESPACE	 := aquasec
NAME 		 := aquasec
BINARY		 := terraform-provider-${NAME}
VERSION      := 0.8.21
OS_ARCH      := $(shell go env GOOS)_$(shell go env GOARCH)

default: build

build:
	go get
	go mod vendor
	go build -ldflags "-X main.version=v${VERSION}" -o ${BINARY}

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

.PHONY: build

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

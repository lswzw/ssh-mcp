# Keep the build cache writable in restricted Unix environments while keeping
# the command and directory setup native on Windows. Callers can still
# override the complete command with `make GO=...`.
ifeq ($(OS),Windows_NT)
GO ?= go
ifneq ($(findstring sh,$(SHELL)),)
MKDIR_P ?= mkdir -p "$(BUILD_DIR)"
else
MKDIR_P ?= if not exist "$(subst /,\,$(BUILD_DIR))" mkdir "$(subst /,\,$(BUILD_DIR))"
endif
else
GO ?= env -u GOROOT GOTOOLCHAIN=local GOCACHE=/tmp/ssh-mcp-go-cache go
MKDIR_P ?= mkdir -p "$(BUILD_DIR)"
endif
BUILD_DIR ?= bin
BUILD_TARGET ?= ./cmd/ssh-mcp
PROGRAM ?= ssh-mcp

# Keep `make` useful for release work while leaving `make build` as the
# host-native development build used by the local workflow.
.DEFAULT_GOAL := all

# GNU Make on native Windows exposes OS=Windows_NT, so the host-native debug
# artifact follows the platform's executable naming convention.
ifeq ($(OS),Windows_NT)
EXE_SUFFIX ?= .exe
else
EXE_SUFFIX ?=
endif
DEBUG_PROGRAM ?= $(PROGRAM).debug$(EXE_SUFFIX)

LINUX_PACKAGE := $(BUILD_DIR)/$(PROGRAM)-linux-amd64
DARWIN_PACKAGE := $(BUILD_DIR)/$(PROGRAM)-darwin-arm64
WINDOWS_PACKAGE := $(BUILD_DIR)/$(PROGRAM)-windows-amd64.exe

.PHONY: all packages build build-debug build-dir build-linux build-darwin build-windows check fmt test vet security

# bin/.gitkeep keeps the output directory in a clean checkout. Target-specific
# exported variables keep cross-build recipes independent of shell syntax.
all: packages

packages: build-linux build-darwin build-windows

build-dir:
	$(MKDIR_P)

build-linux: | build-dir
build-linux: override export CGO_ENABLED = 0
build-linux: override export GOOS = linux
build-linux: override export GOARCH = amd64
build-linux:
	$(GO) build -trimpath -buildvcs=false -ldflags="-s -w" -o "$(LINUX_PACKAGE)" $(BUILD_TARGET)

build-darwin: | build-dir
build-darwin: override export CGO_ENABLED = 0
build-darwin: override export GOOS = darwin
build-darwin: override export GOARCH = arm64
build-darwin:
	$(GO) build -trimpath -buildvcs=false -ldflags="-s -w" -o "$(DARWIN_PACKAGE)" $(BUILD_TARGET)

build-windows: | build-dir
build-windows: override export CGO_ENABLED = 0
build-windows: override export GOOS = windows
build-windows: override export GOARCH = amd64
build-windows:
	$(GO) build -trimpath -buildvcs=false -ldflags="-s -w" -o "$(WINDOWS_PACKAGE)" $(BUILD_TARGET)

build: | build-dir
	$(GO) build -trimpath -buildvcs=false -ldflags="-s -w" -o "$(BUILD_DIR)/" $(BUILD_TARGET)

build-debug: | build-dir
	$(GO) build -trimpath -buildvcs=false -o "$(BUILD_DIR)/$(DEBUG_PROGRAM)" $(BUILD_TARGET)

check: fmt vet test

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

security:
	$(GO) mod verify
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

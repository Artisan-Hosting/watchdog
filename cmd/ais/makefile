# Makefile for ais
# ------------------------------------------------------------
# Regenerate gRPC stubs and build the CLI binary.
# Usage:
#   make           # = proto + build
#   make proto     # regenerate Go code from proto
#   make build     # build binary
#   make run ARGS="--cmd list"   # run with args
#   make clean     # remove generated code and binary
#   make tools     # install protoc plugins if missing
#
# If your proto is a symlink, you can add an extra include dir:
#   make proto REAL_PROTO_DIR=/abs/path/to/real/proto/dir
# ------------------------------------------------------------

SHELL := /bin/bash

# ---- Paths / names ----
MODULE          := ais
BIN             := ais
MAIN            := ./main.go

PROTO_DIR       := proto
PROTO_FILE      := $(PROTO_DIR)/watchdog.proto

# Where generated Go code should live (matches option go_package)
GEN_DIR         := generated
GEN_PKG_DIR     := $(GEN_DIR)/artisan/watchdog

# Extra include dir for symlinked protos (optional)
REAL_PROTO_DIR  ?=

# ---- Tools ----
PROTOC          := protoc
# These should be on PATH after `go install ...`
PROTOC_GEN_GO   := $(shell command -v protoc-gen-go 2>/dev/null)
PROTOC_GEN_GRPC := $(shell command -v protoc-gen-go-grpc 2>/dev/null)

# ---- Flags ----
INC_FLAGS := -I $(PROTO_DIR)
ifneq ($(strip $(REAL_PROTO_DIR)),)
INC_FLAGS += -I $(REAL_PROTO_DIR)
endif

GOFLAGS ?=

# ---- Default ----
.PHONY: all
all: proto build

# ---- Generate stubs ----
.PHONY: proto
proto: tools
	@echo ">> cleaning old generated package"
	@rm -rf $(GEN_PKG_DIR)
	@mkdir -p $(GEN_DIR)
	@echo ">> generating Go protobufs"
	$(PROTOC) $(INC_FLAGS) \
	  --go_out=$(GEN_DIR) \
	  --go-grpc_out=$(GEN_DIR) \
	  $(PROTO_FILE)
	@echo ">> done: $(GEN_PKG_DIR)"

# ---- Build binary ----
.PHONY: build
build:
	@echo ">> building $(BIN)"
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BIN) $(MAIN)
	@echo ">> built ./$(BIN)"

# ---- Run convenience ----
.PHONY: run
run: build
	@echo ">> running ./$(BIN) $(ARGS)"
	./$(BIN) $(ARGS)

# ---- Go mod tidy (optional) ----
.PHONY: tidy
tidy:
	@go mod tidy

# ---- Install/verify tools ----
.PHONY: tools
tools: check-protoc check-protoc-plugins

.PHONY: check-protoc
check-protoc:
	@command -v $(PROTOC) >/dev/null 2>&1 || { \
	  echo "ERROR: protoc not found. Install via your package manager (e.g., apt/brew)"; exit 1; }

.PHONY: check-protoc-plugins
check-protoc-plugins:
	@if [ -z "$(PROTOC_GEN_GO)" ] || [ -z "$(PROTOC_GEN_GRPC)" ]; then \
	  echo ">> installing protoc go plugins"; \
	  GOBIN="$$(go env GOPATH)/bin" ; \
	  echo "   (ensure $$GOBIN is on your PATH)"; \
	  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest ; \
	  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest ; \
	else \
	  echo ">> protoc plugins found"; \
	fi

# ---- Clean ----
.PHONY: clean
clean:
	@echo ">> cleaning generated code and binary"
	@rm -rf $(GEN_DIR) $(BIN)

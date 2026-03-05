BINARY := network-scanner
BIN_DIR := bin
CMD := ./cmd/network-scanner

.PHONY: all build clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY) $(CMD)
	@echo "Built: $(BIN_DIR)/$(BINARY)"

clean:
	rm -rf $(BIN_DIR)

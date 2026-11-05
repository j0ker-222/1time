PROJECT_NAME := 1time
BIN_DIR      := bin
FRONTEND_DIR := frontend
LDFLAGS      := -s -w

.PHONY: all build frontend test test-go test-frontend vet vulncheck clean

all: build frontend

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(PROJECT_NAME) .

frontend:
	cd $(FRONTEND_DIR) && npm ci && npm run build

test: test-go test-frontend

test-go: vet
	go test -race -count=1 ./...

test-frontend:
	cd $(FRONTEND_DIR) && npm ci && npm test

vet:
	go vet ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
	cd $(FRONTEND_DIR) && npm audit --omit=dev

clean:
	rm -rf $(BIN_DIR) $(FRONTEND_DIR)/build

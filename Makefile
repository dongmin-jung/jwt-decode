GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BUILD_DIR=_docker
DOCKER_NAME=tmaxcloudck/jwt-decode
TAG=5.0.0.4
BINARY_NAME=$(BUILD_DIR)/main
MAIN_FILE=cmd/main.go
OUT_DIR=_out
COVER_FILE=$(OUT_DIR)/test.cover
BENCH_N=0
BENCH_TIME=10s
BENCH_MEM_FILE=$(OUT_DIR)/memprofile_$(BENCH_N).out
BENCH_CPU_FILE=$(OUT_DIR)/cpuprofile_$(BENCH_N).out
BENCH_DIR=decoder

all: clean verify build docker
run: docker
	docker run -e JWKS_URL='https://www.googleapis.com/oauth2/v3/certs' -v $(shell pwd)/config.json:/config.json $(DOCKER_NAME):$(TAG)
docker: build
	docker build $(BUILD_DIR) -t $(DOCKER_NAME):$(TAG)
push: docker
	docker push $(DOCKER_NAME):$(TAG)
build: deps
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux GO111MODULE=on $(GOBUILD) -o $(BINARY_NAME) -v $(MAIN_FILE)
verify: race bench
bench: outdir
	$(GOTEST) ./$(BENCH_DIR) -bench=. -benchtime $(BENCH_TIME) -benchmem -memprofile "$(BENCH_MEM_FILE)" -cpuprofile "$(BENCH_CPU_FILE)"
cover: test
	go tool cover -html $(COVER_FILE)
race: deps lint outdir
	$(GOTEST) -coverprofile "$(COVERFILE)" -race ./... -v
test: deps lint outdir
	$(GOTEST) -coverprofile "$(COVER_FILE)" ./... -v
lint:
	go mod tidy
	go fmt ./...
	go vet ./...
outdir:
	mkdir -p $(OUT_DIR)
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BENCH_DIR).test
deps:
	$(GOCMD) mod download

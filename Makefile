.PHONY: proto build build-master build-agent run-master run-agent clean

# Proto 生成
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=./internal/proto --go_opt=paths=source_relative \
		--go-grpc_out=./internal/proto --go-grpc_opt=paths=source_relative \
		-I./proto ./proto/*.proto
	@echo "Proto generation complete."

# 构建所有
build: proto
	@echo "Building all binaries..."
	go build -o bin/master ./cmd/master
	go build -o bin/agent ./cmd/agent
	@echo "Build complete."

# 构建 Master
build-master: proto
	@echo "Building master..."
	go build -o bin/master ./cmd/master
	@echo "Master built successfully."

# 构建 Agent
build-agent: proto
	@echo "Building agent..."
	go build -o bin/agent ./cmd/agent
	@echo "Agent built successfully."

# 运行 Master
run-master: build-master
	@echo "Starting master..."
	./bin/master

# 运行 Agent
run-agent: build-agent
	@echo "Starting agent..."
	./bin/agent

# 清理
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf internal/proto/*.go
	@echo "Clean complete."

# 安装工具
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Docker 构建
docker-build-master:
	docker build -t dasrs-master -f deploy/Dockerfile.master .

docker-build-agent:
	docker build -t dasrs-agent -f deploy/Dockerfile.agent .

docker-up:
	docker-compose -f deploy/docker-compose up -d

docker-down:
	docker-compose -f deploy/docker-compose down

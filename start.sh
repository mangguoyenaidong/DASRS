#!/bin/bash

# DASRS 一键智能启动脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}   🛡️  DASRS 自动化环境检查与启动工具${NC}"
echo -e "${BLUE}=======================================${NC}"

# 1. 检查并安装环境
echo -e "\n${YELLOW}[1/4] 检查运行环境...${NC}"

check_tool() {
    if ! command -v $1 &> /dev/null; then
        return 1
    fi
    return 0
}

# 检查 Go
if check_tool go; then
    echo -e "${GREEN}✓ Go 已安装: $(go version | awk '{print $3}')${NC}"
else
    echo -e "${RED}✗ 未找到 Go。请先安装 Go 1.21+ (https://go.dev/doc/install)${NC}"
    exit 1
fi

# 检查 Docker
if check_tool docker; then
    echo -e "${GREEN}✓ Docker 已安装${NC}"
else
    echo -e "${YELLOW}! 未找到 Docker。基础设施（MySQL/Redis）可能无法自动启动。${NC}"
fi

# 检查 Python 依赖
if ! python3 -c "import ruamel.yaml" &> /dev/null; then
    echo -e "${YELLOW}! 缺少 Python 库: ruamel.yaml，正在安装...${NC}"
    sudo apt update && sudo apt install -y python3-pip
    pip3 install ruamel.yaml --quiet
fi

# 检查 Protoc
if check_tool protoc; then
    echo -e "${GREEN}✓ Protoc 已安装${NC}"
else
    echo -e "${YELLOW}! 未找到 protoc。正在尝试安装...${NC}"
    sudo apt update && sudo apt install -y protobuf-compiler
fi

# 检查 Go 插件
GOPATH_BIN=$(go env GOPATH)/bin
export PATH=$PATH:$GOPATH_BIN

if [ ! -f "$GOPATH_BIN/protoc-gen-go" ]; then
    echo -e "${YELLOW}! 缺失 Go Protobuf 插件。正在安装...${NC}"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    
    # 写入 shell 配置文件以持久化
    SHELL_RC="$HOME/.bashrc"
    [[ $SHELL == *"zsh"* ]] && SHELL_RC="$HOME/.zshrc"
    if ! grep -q "go/bin" "$SHELL_RC"; then
        echo "export PATH=\$PATH:$GOPATH_BIN" >> "$SHELL_RC"
    fi
fi

# 2. 交互式配置
echo -e "\n${YELLOW}[2/4] 配置确认...${NC}"

RUN_CONFIG=false
if [ ! -f "configs/config.yaml" ] || [ ! -f "configs/agent.yaml" ]; then
    echo -e "${BLUE}检测到首次运行，正在进入配置模式...${NC}"
    RUN_CONFIG=true
else
    read -t 10 -p "是否需要更改配置 (IP、数据库、名称等)? [y/N]: " change_cfg
    if [[ "$change_cfg" =~ ^[Yy]$ ]]; then
        RUN_CONFIG=true
    fi
fi

if [ "$RUN_CONFIG" = true ]; then
    python3 configure.py
fi

# 3. 编译二进制文件
echo -e "\n${YELLOW}[3/4] 编译程序...${NC}"
make build
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ 编译失败，请检查上方代码错误。${NC}"
    exit 1
fi
echo -e "${GREEN}✓ 编译成功。${NC}"

# 4. 启动服务
echo -e "\n${YELLOW}[4/4] 启动服务...${NC}"
echo "请选择启动模式:"
echo "1) 启动 Master (含数据库/Redis)"
echo "2) 启动 Agent (边缘监控)"
echo "3) 同时启动 Master 和 Agent"
echo "q) 退出"
read -p "选择 [1-3/q]: " choice

case $choice in
    1)
        echo -e "${BLUE}正在拉起基础设施 (Docker)...${NC}"
        cd deploy && docker-compose up -d && cd ..
        echo -e "${GREEN}启动 Master 节点...${NC}"
        ./bin/master
        ;;
    2)
        echo -e "${GREEN}启动 Agent 节点 (由于需要操作防火墙，请授权 sudo)...${NC}"
        sudo ./bin/agent
        ;;
    3)
        echo -e "${BLUE}正在拉起基础设施 (Docker)...${NC}"
        cd deploy && docker-compose up -d && cd ..
        echo -e "${GREEN}启动 Master 节点 (后台运行，日志记录在 master.log)...${NC}"
        nohup ./bin/master > master.log 2>&1 &
        echo -e "${GREEN}启动 Agent 节点 (当前窗口)...${NC}"
        sudo ./bin/agent
        ;;
    *)
        echo "退出程序。"
        exit 0
        ;;
esac

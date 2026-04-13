#!/bin/bash

# DASRS 一键智能启动脚本 (增强版：含 Suricata 自动化)

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
    echo -e "${GREEN}✓ Go 已安装${NC}"
else
    echo -e "${RED}✗ 未找到 Go。请先安装 Go 1.21+${NC}"
    exit 1
fi

# 检查 Python 依赖
if ! python3 -c "import ruamel.yaml" &> /dev/null; then
    echo -e "${YELLOW}! 缺少 Python 库: ruamel.yaml，正在安装...${NC}"
    sudo apt update && sudo apt install -y python3-pip
    pip3 install ruamel.yaml --quiet
fi

# 检查 Suricata (Agent 端必需)
if check_tool suricata; then
    echo -e "${GREEN}✓ Suricata 已安装: $(suricata -V | awk '{print $NF}')${NC}"
else
    echo -e "${YELLOW}! 未找到 Suricata。检测到您可能需要在此机器运行 Agent。${NC}"
    read -p "是否现在自动安装并配置 Suricata? [y/N]: " install_suricata
    if [[ "$install_suricata" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}正在安装 Suricata...${NC}"
        sudo apt update && sudo apt install -y suricata
        echo -e "${BLUE}正在更新 Suricata 签名规则...${NC}"
        sudo suricata-update
        echo -e "${GREEN}✓ Suricata 安装完成。${NC}"
    fi
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
    echo -e "${YELLOW}! 缺失 Go 插件。正在安装...${NC}"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# 2. 交互式配置
echo -e "\n${YELLOW}[2/4] 配置确认...${NC}"

RUN_CONFIG=false
if [ ! -f "configs/config.yaml" ] || [ ! -f "configs/agent.yaml" ]; then
    RUN_CONFIG=true
else
    read -t 10 -p "是否需要更改配置 (IP、数据库、网卡等)? [y/N]: " change_cfg
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
    echo -e "${RED}✗ 编译失败，请检查代码错误。${NC}"
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
        cd deploy && docker-compose up -d && cd ..
        ./bin/master
        ;;
    2)
        sudo ./bin/agent
        ;;
    3)
        cd deploy && docker-compose up -d && cd ..
        nohup ./bin/master > master.log 2>&1 &
        sudo ./bin/agent
        ;;
    *)
        exit 0
        ;;
esac

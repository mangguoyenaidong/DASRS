#!/bin/bash

# DASRS 一键智能启动脚本 (优化版：按需编译)

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
echo -e "\n${YELLOW}[1/3] 检查运行环境...${NC}"

check_tool() {
    if ! command -v $1 &> /dev/null; then return 1; fi
    return 0
}

# 自动配置 Go 代理
go env -w GOPROXY=https://goproxy.cn,direct

if check_tool go; then
    echo -e "${GREEN}✓ Go 已就绪${NC}"
else
    echo -e "${RED}✗ 未找到 Go${NC}"; exit 1
fi

# 检查 Python 依赖
if ! python3 -c "import ruamel.yaml" &> /dev/null; then
    echo -e "${YELLOW}! 正在准备配置工具依赖...${NC}"
    sudo apt update && sudo apt install -y python3-pip
    pip3 install ruamel.yaml --quiet
fi

# 2. 交互式配置
echo -e "\n${YELLOW}[2/3] 配置确认...${NC}"
RUN_CONFIG=false
if [ ! -f "configs/config.yaml" ] || [ ! -f "configs/agent.yaml" ]; then
    RUN_CONFIG=true
else
    read -t 10 -p "是否需要更改配置 (IP、数据库、网卡等)? [y/N]: " change_cfg
    if [[ "$change_cfg" =~ ^[Yy]$ ]]; then RUN_CONFIG=true; fi
fi

if [ "$RUN_CONFIG" = true ]; then
    python3 configure.py
fi

# 3. 选择启动模式并按需编译
echo -e "\n${YELLOW}[3/3] 启动服务模式选择...${NC}"
echo "1) 仅启动 Master (中枢/Web/数据库)"
echo "2) 仅启动 Agent (边缘采集/防护)"
echo "3) 同时启动 Master 和 Agent"
echo "q) 退出"
read -p "选择 [1-3/q]: " choice

case $choice in
    1)
        echo -e "${BLUE}正在拉起基础设施 (Docker)...${NC}"
        cd deploy && docker-compose up -d && cd ..
        echo -e "${BLUE}按需编译 Master...${NC}"
        make build-master
        echo -e "${GREEN}启动 Master 节点...${NC}"
        ./bin/master
        ;;
    2)
        echo -e "${BLUE}按需编译 Agent...${NC}"
        make build-agent
        echo -e "${GREEN}启动 Agent 节点...${NC}"
        sudo ./bin/agent
        ;;
    3)
        echo -e "${BLUE}正在拉起基础设施 (Docker)...${NC}"
        cd deploy && docker-compose up -d && cd ..
        echo -e "${BLUE}正在编译所有组件...${NC}"
        make build
        echo -e "${GREEN}正在启动集群服务...${NC}"
        nohup ./bin/master > master.log 2>&1 &
        echo -e "${YELLOW}Master 已转入后台 (日志: master.log)${NC}"
        sudo ./bin/agent
        ;;
    *)
        echo "退出。"
        exit 0
        ;;
esac

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

ensure_suricata_payload_logging() {
    local suricata_conf="/etc/suricata/suricata.yaml"

    if [ ! -f "$suricata_conf" ]; then
        echo -e "${YELLOW}! 未检测到 $suricata_conf，跳过 Suricata 自动配置${NC}"
        return 0
    fi

    echo -e "${BLUE}正在检查 Suricata 告警报文输出配置...${NC}"

    local tmp_file
    tmp_file=$(mktemp)
    cp "$suricata_conf" "$tmp_file"

    sed -Ei '/- alert:/,/tagged-packets:/ {
        s/^([[:space:]]*)#?[[:space:]]*payload:[[:space:]].*/\1payload: yes/
        s/^([[:space:]]*)#?[[:space:]]*payload-printable:[[:space:]].*/\1payload-printable: yes/
        s/^([[:space:]]*)#?[[:space:]]*packet:[[:space:]].*/\1packet: yes/
    }' "$tmp_file"

    if cmp -s "$suricata_conf" "$tmp_file"; then
        echo -e "${GREEN}✓ Suricata payload 输出已开启${NC}"
        rm -f "$tmp_file"
        return 0
    fi

    echo -e "${YELLOW}! 检测到 Suricata 配置需要更新，正在应用...${NC}"
    sudo cp "$suricata_conf" "${suricata_conf}.bak.$(date +%Y%m%d%H%M%S)"
    sudo cp "$tmp_file" "$suricata_conf"
    rm -f "$tmp_file"

    if sudo suricata -T -c "$suricata_conf" > /tmp/dasrs-suricata-check.log 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart suricata
        else
            sudo service suricata restart
        fi
        echo -e "${GREEN}✓ 已开启 payload / payload-printable / packet 输出并重启 Suricata${NC}"
    else
        echo -e "${RED}✗ Suricata 配置校验失败，保留备份并停止启动${NC}"
        echo -e "${RED}  详情请查看 /tmp/dasrs-suricata-check.log${NC}"
        return 1
    fi
}

extract_agent_monitor_ip() {
    python3 - <<'PY'
from pathlib import Path
import sys

try:
    from ruamel.yaml import YAML
except Exception:
    print("")
    sys.exit(0)

path = Path("configs/agent.yaml")
if not path.exists():
    print("")
    sys.exit(0)

yaml = YAML(typ="safe")
data = yaml.load(path.read_text(encoding="utf-8")) or {}
agent = data.get("agent") or {}
print((agent.get("monitor_ip") or "").strip())
PY
}

ensure_agent_monitor_ip() {
    local agent_conf="configs/agent.yaml"

    if [ ! -f "$agent_conf" ]; then
        echo -e "${YELLOW}! 未检测到 $agent_conf，跳过 monitor_ip 校验${NC}"
        return 0
    fi

    local monitor_ip
    monitor_ip=$(extract_agent_monitor_ip)

    if [ -z "$monitor_ip" ]; then
        echo -e "${YELLOW}! 当前未配置 monitor_ip，Agent 将不会按目标主机定向过滤${NC}"
        return 0
    fi

    echo -e "${BLUE}当前 Agent monitor_ip: ${monitor_ip}${NC}"

    if ! ip addr | grep -F " ${monitor_ip}/" > /dev/null 2>&1; then
        echo -e "${YELLOW}! monitor_ip (${monitor_ip}) 不属于当前主机网卡地址${NC}"
        echo -e "${YELLOW}! 这会导致 Agent 可能过滤掉真正的攻击告警，请确认 configs/agent.yaml 配置${NC}"
    else
        echo -e "${GREEN}✓ monitor_ip 与当前主机网卡一致${NC}"
    fi
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
        ensure_suricata_payload_logging || exit 1
        ensure_agent_monitor_ip
        echo -e "${GREEN}启动 Agent 节点...${NC}"
        sudo ./bin/agent
        ;;
    3)
        echo -e "${BLUE}正在拉起基础设施 (Docker)...${NC}"
        cd deploy && docker-compose up -d && cd ..
        echo -e "${BLUE}正在编译所有组件...${NC}"
        make build
        ensure_suricata_payload_logging || exit 1
        ensure_agent_monitor_ip
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

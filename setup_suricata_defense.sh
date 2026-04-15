#!/bin/bash

# =================================================================
# DASRS - Suricata 自动化防御精简配置脚本
# 功能: 1. 锁定监控 IP 2. 只开启 Nmap 与 HTTP 漏洞规则 3. 优化性能
# =================================================================

TARGET_IP="192.168.41.136"
SURICATA_CONF="/etc/suricata/suricata.yaml"
CUSTOM_RULES="/etc/suricata/rules/custom.rules"

# 检查权限
if [ "$EUID" -ne 0 ]; then 
  echo "请使用 sudo 运行此脚本"
  exit 1
fi

echo "[1/5] 正在备份原始配置..."
if [ -f "$SURICATA_CONF" ]; then
    cp "$SURICATA_CONF" "${SURICATA_CONF}.bak"
else
    echo "错误: 未找到 Suricata 配置文件 $SURICATA_CONF"
    exit 1
fi

echo "[2/5] 正在配置受保护网络 (HOME_NET) 为 $TARGET_IP..."
# 替换 HOME_NET 变量
sed -i "s/HOME_NET: .*/HOME_NET: \"[$TARGET_IP]\"/" $SURICATA_CONF
# 确保 EXTERNAL_NET 设置正确
sed -i "s/EXTERNAL_NET: .*/EXTERNAL_NET: \"!\$HOME_NET\"/" $SURICATA_CONF

echo "[3/5] 正在精简规则加载列表 (仅保留 Scanners 和 HTTP)..."
# 先注释掉所有默认规则
sed -i 's/^- /# - /' $SURICATA_CONF 

# 检查是否已有 rule-files 块，如果没有则添加，如果有则追加
if ! grep -q "rule-files:" "$SURICATA_CONF"; then
    echo "rule-files:" >> "$SURICATA_CONF"
fi

cat << 'RE' >> $SURICATA_CONF
  - scanners.rules
  - http-events.rules
  - server-http.rules
  - web-server.rules
  - exploit.rules
  - custom.rules
RE

echo "[4/5] 正在添加高保真自定义规则 (针对 Nmap 和常见 Web 攻击)..."
mkdir -p /etc/suricata/rules
cat << 'CR' > $CUSTOM_RULES
# --- NMAP 扫描检测 ---
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"[DASRS] NMAP TCP Scan (Flags: SF)"; flags:SF; sid:1000001; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"[DASRS] Nmap Scripting Engine (NSE) Scan"; http.user_agent; content:"Nmap"; sid:1000002; rev:1;)

# --- HTTP 漏洞利用检测 ---
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"[DASRS] Path Traversal Attempt (/etc/passwd)"; http.uri; content:"/etc/passwd"; sid:1000003; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"[DASRS] SQL Injection Attempt (UNION SELECT)"; http.uri; content:"union select"; nocase; sid:1000004; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"[DASRS] WebShell Execution Attempt (whoami)"; http.uri; content:"whoami"; sid:1000005; rev:1;)
CR

echo "[5/5] 正在验证配置并重启 Suricata..."
suricata -T -c $SURICATA_CONF > /dev/null 2>&1
if [ $? -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart suricata
    else
        service suricata restart
    fi
    echo "===================================================="
    echo "配置完成！"
    echo "1. 目标 IP: $TARGET_IP"
    echo "2. 规则集: 已精简为 Scanners & HTTP"
    echo "3. 自定义规则: 已保存至 $CUSTOM_RULES"
    echo "===================================================="
else
    echo "错误: Suricata 配置语法检查失败，已回退配置。"
    cp "${SURICATA_CONF}.bak" "$SURICATA_CONF"
    exit 1
fi

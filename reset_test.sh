#!/bin/bash

# DASRS 测试环境重置脚本
# 作用：清空所有告警数据，重置采集进度，准备进行新一轮测试。

echo "--- 正在重置 DASRS 测试环境 ---"

# 1. 停止 Master 和 Agent (根据进程名查找)
echo "[1/4] 正在关闭现有进程..."
pkill -f "cmd/master" || true
pkill -f "cmd/agent" || true
sleep 1

# 2. 清理 Agent 偏移量文件
echo "[2/4] 正在重置 Agent 采集进度..."
rm -f .suricata_*.offset
echo "✅ 已删除所有 .offset 文件"

# 3. 清理数据库 (需要系统中已配置 mysql 客户端环境)
# 注意：这里假设你使用的是默认配置，如果不是，请手动修改
DB_NAME="security_system" # 请根据 configs/config.yaml 中的数据库名确认
echo "[3/4] 正在清空数据库告警表 ($DB_NAME)..."
mysql -e "USE $DB_NAME; TRUNCATE TABLE alerts; TRUNCATE TABLE audit_logs;" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ 数据库已清空"
else
    echo "❌ 数据库清空失败 (请检查 mysql 权限或手动执行 TRUNCATE TABLE alerts)"
fi

# 4. 清理 Redis
echo "[4/4] 正在清空 Redis 评分数据..."
redis-cli FLUSHALL 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Redis 已重置"
else
    echo "❌ Redis 清空失败 (请检查 redis-server 是否运行)"
fi

echo "--- 重置完成！您可以重新启动服务进行测试了 ---"
echo "启动命令示例："
echo "  Master: go run ./cmd/master/main.go"
echo "  Agent:  go run ./cmd/agent/main.go --config configs/agent.yaml"

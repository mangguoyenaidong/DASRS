# DASRS 使用文档 (v1.2.0)

DASRS (Distributed Intelligence-Driven Emergency Response System) - 分布式情报驱动应急响应系统。

## 1. 系统概览

DASRS 是一个自动化安全响应系统，通过 Master-Agent 架构实现以下功能：
- **实时采集**: 监控 Suricata EVE JSON 告警。
- **智能分析**: 基于风险评分、时序频率与资产上下文进行决策。
- **自动化阻断**: 支持 IPTables IP 封禁与 Nginx 配置文件原子性热修复。
- **可视化审计**: 提供 Hex/Text 双模报文审计与人工判定功能。

## 2. 快速部署

### 2.1 环境准备
- **操作系统**: Linux (推荐 Ubuntu 20.04+)
- **软件依赖**: Docker, Docker Compose, Go 1.25+, Python 3 (含 `ruamel.yaml`)

### 2.2 交互式配置 (推荐)
系统提供配置助手，可自动完成网卡绑定与通信地址配置：
```bash
# 安装依赖
pip install ruamel.yaml

# 启动配置助手
python3 configure.py
```
*根据提示输入 MySQL/Redis 地址及 Master IP 即可。*

### 2.3 启动基础设施 (Docker)
```bash
cd deploy
docker-compose up -d
```

### 2.4 启动服务
```bash
# 启动 Master (服务端)
go run ./cmd/master

# 启动 Agent (客户端)
go run ./cmd/agent --config configs/agent.yaml
```

## 3. 管理后台操作指南

访问地址: `http://localhost:8080` (或 Master 实际 IP)

### 3.1 资产管理
- 查看所有 Agent 的在线状态、IP 及服务类型。
- 状态脉冲：绿色表示心跳正常，灰色表示离线。

### 3.2 告警审计
- **详情审计**: 点击告警行的“审计”按钮，弹出深度分析窗口。
- **Payload 解析**: 自动解码 Base64 原始流量，支持 **Text 视图** (高亮关键词) 和 **Hex 视图** (十六进制对照)。
- **人工干预**: 审计窗口提供“立即封禁”或“加入白名单”的一键处置按钮。

### 3.3 白名单管理 (New)
- **保护机制**: 加入白名单的 IP，其风险评分将被引擎强制归 0，避免误封。
- **应用场景**: 内部扫描器、办公网出口 IP 或已知安全合作伙伴。
- **操作**: 在“白名单管理”菜单中通过 IP 和备注进行动态增删。

### 3.4 策略管理
- 定义针对特定 SID 的自动化修复策略。
- 示例：若命中 SQL 注入告警，自动在 Nginx 配置中对该路径添加 `deny all` 或 `allow <trusted_ip>`。

## 4. API 参考 (部分)

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/stats` | GET | 获取全局统计数据 |
| `/api/alerts` | GET | 告警列表 (支持 source_ip, severity 等过滤) |
| `/api/whitelist` | POST | 动态添加 IP 到白名单 |
| `/api/block` | POST | 手动下发全球封禁指令 |
| `/api/unblock` | POST | 手动下发全球解封指令 |

## 5. 常见问题排查 (FAQ)

**Q: Agent 无法连接到 Master？**
A: 检查 `configs/agent.yaml` 中的 `master_address` 是否为正确的 IP:Port。如果不在 Docker 网络，请勿使用 `master:50051` 这种主机名。

**Q: 配置文件修复失败？**
A: 确保 Agent 以 root 权限运行（执行 `nginx -t` 需要权限），且配置路径在 `agent.yaml` 的允许范围内。

**Q: 为什么某些告警没有触发封禁？**
A: 检查风险评分是否达到了 `block_threshold` (默认 50)。低严重程度告警需要触发频率加成才能达到封禁阈值。

---
*DASRS 致力于构建更智能、更快速的防御闭环。*

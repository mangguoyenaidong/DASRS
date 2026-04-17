# DASRS 使用文档

## 1. 系统概览

DASRS (Distributed Intelligence-Driven Emergency Response System) 是一个基于 Master-Agent 架构的分布式安全响应系统。

核心能力包括：

- 实时采集 Suricata EVE JSON 告警
- 基于风险评分、时序频率和白名单进行决策
- 通过在线 Agent 执行 IP 封禁与解封
- 支持 Nginx 配置文件原子性热修复
- 提供 Web 管理后台、告警审计与白名单管理

## 2. 运行环境

- 操作系统：Linux（推荐 Ubuntu 20.04+）
- Go：1.25+
- Python：3.x
- 数据库：MySQL 8.0
- 缓存：Redis 7.0
- 容器环境：Docker、Docker Compose

如需使用交互式配置助手：

```bash
pip install ruamel.yaml
```

## 3. 配置说明

### 3.1 Master 配置

文件：`configs/config.yaml`

主要配置项：

- `master.host`：HTTP 服务绑定地址
- `master.grpc_port`：gRPC 监听端口
- `master.http_port`：HTTP API 监听端口
- `master.database.*`：MySQL 连接配置
- `master.redis.*`：Redis 连接配置
- `master.intelligence.block_threshold`：自动封禁阈值
- `master.intelligence.repair_threshold`：自动修复阈值
- `master.intelligence.whitelist`：静态白名单

### 3.2 Agent 配置

文件：`configs/agent.yaml`

主要配置项：

- `agent.master_address`：Master 的可达地址，格式为 `IP:PORT` 或域名
- `agent.suricata_log_path`：Suricata `eve.json` 路径
- `agent.monitor_ip`：仅采集发往该 IP 的告警，可用于多主机环境中的定向过滤
- `agent.agent_name`：Agent 名称
- `agent.reconnect_interval`：重连间隔（秒）
- `agent.heartbeat_interval`：心跳间隔（秒）

注意：

- `master:50051` 这类地址仅适用于 Docker 内部网络。
- 在非 Docker 或跨主机部署中，请将 `master_address` 改为 Master 的实际 IP 或域名。
- 如果未正确设置 `monitor_ip`，可能会采集到不属于当前节点的告警流量。

### 3.3 交互式配置

推荐先执行：

```bash
python3 configure.py
```

该脚本可辅助更新：

- `configs/config.yaml`
- `configs/agent.yaml`
- 本地 Suricata 网卡绑定与 Payload 输出配置

## 4. 启动方式

### 4.1 启动基础设施

```bash
cd deploy
docker-compose up -d
```

### 4.2 启动 Master

```bash
go run ./cmd/master --config configs/config.yaml
```

默认监听：

- gRPC：`50051`
- HTTP：`8080`

### 4.3 启动 Agent

```bash
go run ./cmd/agent --config configs/agent.yaml
```

如需仅测试 Agent 到 Master 的连通性：

```bash
go run ./cmd/agent --config configs/agent.yaml --test-master-conn
```

## 5. Docker 部署说明

`deploy/docker-compose.yaml` 默认包含以下服务：

- `mysql`
- `redis`
- `master`
- `agent`

默认约定：

- Master 对外暴露 `50051` 和 `8080`
- Agent 通过 `MASTER_ADDRESS=master:50051` 连接容器内 Master
- 示例 Agent 挂载 `../suricata_logs` 作为 Suricata 日志目录

如果是跨机器部署，不要直接照搬容器内的 `master:50051`，应改为真实地址。

## 6. 管理后台

默认访问地址：

- `http://localhost:8080`

远程部署时，请替换为 Master 的实际 IP 或域名，例如：

- `http://<master-host>:8080`

后台主要功能：

- 资产管理：查看 Agent 在线状态、名称、IP 与注册信息
- 告警审计：查看告警详情、Payload、Hex/Text 双视图
- 手动处置：手动封禁、解封、批量操作
- 白名单管理：动态增删白名单 IP
- 策略管理：查看和维护自动化策略
- 仪表盘：查看趋势、攻击源、严重程度分布和执行统计

## 7. API 参考

### 7.1 基础接口

| 路径 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/stats` | GET | 获取全局统计数据 |
| `/api/logs` | GET | 获取操作日志 |

### 7.2 Agent 管理

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/agents` | GET | 获取 Agent 列表 |
| `/api/agents/:id` | GET | 获取 Agent 详情 |
| `/api/agents/:id` | DELETE | 删除 Agent |
| `/api/agents/:id/unblock` | POST | 解除指定 Agent 相关封禁 |
| `/api/agents/register` | POST | Agent 注册/更新 |

### 7.3 告警管理

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/alerts` | GET | 获取告警列表，支持多种过滤条件 |
| `/api/alerts/:id` | GET | 获取单条告警详情 |
| `/api/alerts/:id/correlation` | GET | 获取告警关联分析 |

### 7.4 手动处置

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/block` | POST | 手动封禁单个 IP |
| `/api/unblock` | POST | 手动解封单个 IP |
| `/api/batch-block` | POST | 批量封禁 IP |
| `/api/batch-unblock` | POST | 批量解封 IP |

### 7.5 白名单管理

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/whitelist` | GET | 获取白名单列表 |
| `/api/whitelist` | POST | 添加白名单 IP |
| `/api/whitelist/:id` | DELETE | 删除白名单记录 |

### 7.6 策略与仪表盘

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/strategies` | GET | 获取策略列表 |
| `/api/strategies` | POST | 创建策略 |
| `/api/strategies/:id` | GET | 获取策略详情 |
| `/api/strategies/:id` | PUT | 更新策略 |
| `/api/strategies/:id` | DELETE | 删除策略 |
| `/api/dashboard/overview` | GET | 仪表盘概览 |
| `/api/dashboard/trends` | GET | 攻击趋势 |
| `/api/dashboard/top-sources` | GET | Top 攻击源 |
| `/api/dashboard/severity-distribution` | GET | 严重程度分布 |
| `/api/dashboard/action-stats` | GET | 动作执行统计 |

## 8. 常见问题排查

**Q: Agent 无法连接到 Master？**

A: 先检查 `configs/agent.yaml` 中的 `master_address` 是否为当前环境下真实可达的地址。如果不在 Docker 内部网络，请不要使用 `master:50051`。也可以执行：

```bash
go run ./cmd/agent --config configs/agent.yaml --test-master-conn
```

**Q: 为什么 Agent 启动后没有采集到告警？**

A: 检查 `suricata_log_path` 是否存在，Agent 启动日志会提示路径不存在；同时确认 `monitor_ip` 是否配置为当前节点需要监控的目标 IP。

**Q: 为什么某些告警没有触发封禁？**

A: 检查风险评分是否达到 `block_threshold`。低严重程度告警通常需要频率加成后才会越过封禁阈值；白名单 IP 会被直接忽略。

**Q: 配置文件修复失败？**

A: 确保 Agent 具备所需权限，例如执行 `nginx -t`、reload 或变更防火墙规则时通常需要更高权限，并确认配置文件路径与挂载目录正确。

## 9. 文档边界

## 10. 2026-04 Recent Usage Updates

### 10.1 Agent Service Discovery

The Agent now supports local service discovery on Linux. After startup, it performs an initial scan and then reports the latest service inventory on a schedule.

New configuration items under the Agent section:

```yaml
agent:
  master_http_address: "192.168.41.136:8080"
  agent_name: "agent-136"
  service_scan_interval: 300
```

Notes:
- `master_http_address` is used for HTTP registration and service inventory reporting.
- If `master_http_address` is not provided, the Agent will try to derive it from `master_address`.
- `service_scan_interval` is in seconds.

### 10.2 Viewing Services in the Web Console

On the asset page, clicking the node status opens a node detail panel. The panel now shows:

- basic node information
- current service inventory
- inferred service types

This is the main entry point for checking which services exist on a node.

### 10.3 Lightweight Asset Fingerprint

The service discovery result is also used to enrich the asset profile. The current lightweight fingerprint can update:

- `os_type`
- `service_type`
- node `service_inventory`

For Java processes, the system can now further distinguish several common service types instead of showing only `java-service`, including:

- `tomcat`
- `jenkins`
- `nacos`
- `spring-boot`
- `elasticsearch`
- `kafka`

### 10.4 Updated Alert Scoring Logic

The alert scoring logic has been adjusted to be more conservative and more context-aware.

Current base scores:

- `critical = 80`
- `high = 60`
- `medium = 35`
- `low = 15`

Current formula:

```text
final score = base score + target-service context score + time-series score
```

Target-service context score:

- obvious match: `+20`
- obvious mismatch: `-20`
- unclear: `0`

This allows the system to consider whether the attack signature actually matches the service exposed by the destination host, which helps reduce false positives.

本文件聚焦“如何部署和使用当前系统”。如果你需要了解某次迭代的背景和问题记录，请查看根目录的开发日志文档。

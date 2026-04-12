# DASRS 使用文档

DASRS (Distributed Intelligence-Driven Emergency Response System) - 分布式情报驱动应急响应系统

## 系统概述

DASRS 是一个安全响应系统，提供以下核心功能：
- **Suricata 日志采集** - 实时收集 Suricata EVE JSON 告警日志
- **智能风险评估** - 基于情报引擎的自动风险评分
- **自动化响应** - IPTables IP 封禁 + Nginx 配置热补丁
- **分布式架构** - Master-Agent 双向流 gRPC 通信

## 快速开始

### 1. 环境要求

- Docker & Docker Compose
- Go 1.25+ (开发环境)
- MySQL 8.0+ / Redis 7.0+ (通过 Docker 提供)

### 2. 启动服务

```bash
# 构建并启动所有服务
cd deploy
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 3. 访问管理界面

打开浏览器访问：http://localhost:8080/

## 服务端口

| 服务 | 端口 | 说明 |
|------|------|------|
| Master HTTP | 8080 | REST API + 管理界面 |
| Master gRPC | 50051 | Agent 通信接口 |
| MySQL | 3307 | 数据库 (映射) |
| Redis | 6379 | 缓存/消息队列 |

### 仪表盘
系统概览，支持 **实时动态刷新**，功能包括：
- **实时监控状态栏**：支持开关自动刷新，可选频率 (5秒, 10秒, 30秒, 1分钟)。
- 在线资产数量 / 总告警数 / 待处理告警。
- 已封禁 IP 数量 (基于 iptables)。
- 告警趋势图 (Chart.js 实时渲染)。

### 资产管理
查看所有注册的 Agent 资产信息，支持页面自动同步：
- IP 地址 / 主机名 / 操作系统类型。
- 服务类型 (Nginx/IIS/Apache)。
- 在线状态 (实时脉冲心跳指示器)。

### 策略管理
防护策略列表，支持中文描述（已修复乱码问题）：
- **自动化漏洞修复**：当告警风险评分达到修复阈值（默认 80）时，Master 将自动检索匹配的 SID 策略并下发 `PATCH_CONFIG` 指令。
- **配置热修复**：Agent 遵循“备份-修改-验证-重载”流程。
- 启用/禁用策略。

**添加策略示例：**
```json
{
  "sid": "2000001",
  "target_file": "/etc/nginx/sites-available/default",
  "match_regex": "location /admin",
  "replace_content": "location /admin\n    allow 127.0.0.1;\n    deny all;",
  "description": "限制敏感路径访问"
}
```

### 告警中心
- 查看所有安全告警。
- **原始报文审计**：点击告警行的“详情”按钮，可查看 Base64 解码后的攻击报文，支持 **文本视图 (Text View)** 和 **十六进制视图 (Hex View)**，便于人工分析。
- **人工判定与响应**：在详情窗口提供“判定误报”和“确认攻击”按钮。点击“确认攻击”可手动触发对威胁源 IP 的即时封禁。
- **动态联动**：在告警列表中可一键跳转至封禁页面，自动填入威胁 IP。

...

## 攻击模拟与验证指南

为了验证 DASRS 的响应逻辑，您可以在实验环境中模拟以下攻击：

### 1. 模拟 SQL 注入 (Web 流量)
```bash
# 在另一台机器执行
curl "http://<AGENT_IP>/?id=1' AND 1=1 UNION SELECT NULL,username,password FROM users--"
```

### 2. 模拟日志注入 (本地测试)
向 Agent 的 `eve.json` 路径追加如下 JSON 以触发高风险告警：
```bash
echo '{"timestamp":"2026-04-03T15:00:00.000000+0800","event_type":"alert","src_ip":"1.2.3.4","alert":{"signature_id":2000001,"signature":"Simulated SQL Injection","severity":1}}' >> /var/log/suricata/eve.json
```

### 3. 漏洞扫描器测试
使用 `nmap` 或 `AWVS` 对 Agent 进行全扫描。由于系统具备 **时序频率分析引擎**，短时间内的高频告警会触发加成评分，从而快速阻断扫描源。

## 技术规范说明

### 字符编码
系统全面采用 **UTF-8 (utf8mb4)** 编码规范：
- **数据库**：所有表默认字符集为 `utf8mb4`，Master 连接 DSN 包含 `charset=utf8mb4`，且连接会话显式执行 `SET NAMES utf8mb4`。
- **API 响应**：使用 Gin 的 `PureJSON` 进行序列化，确保中文字符不被 Unicode 转义，保持原始输出。
- **前端渲染**：设置 `<meta charset="UTF-8">`，确保浏览器正确显示多语言描述。

### 实时性保障
- 前端采用 **动态页面轮询机制**，在页面切换时立即刷新数据并重置定时器。
- API 调用采用 `Promise.all` 并发请求，极大缩短了多表统计时的响应时间。

## API 参考

手动封禁指定 IP 地址：
```bash
# API 方式
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "检测到恶意扫描"}'
```

### 操作日志
查看系统操作记录，包括：
- 命令执行结果
- 操作时间戳
- 命令类型

## API 参考

### 基础信息

- Base URL: `http://localhost:8080`
- 响应格式: JSON
- 认证: 无

### 端点列表

#### GET /api/stats
获取系统统计信息

**响应示例:**
```json
{
  "data": {
    "total_assets": 3,
    "online_assets": 3,
    "total_alerts": 0,
    "pending_alerts": 0,
    "blocked_ips": 0,
    "total_strategies": 2,
    "enabled_strategies": 2
  }
}
```

#### GET /api/agents
获取 Agent 资产列表

**参数:**
| 参数 | 类型 | 说明 |
|------|------|------|
| page | int | 页码 (默认 1) |
| page_size | int | 每页数量 (默认 20) |
| search | string | 搜索关键词 |
| service_type | string | 服务类型过滤 |
| status | int | 状态过滤 |

**响应示例:**
```json
{
  "data": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "hostname": "web-server-01",
      "os_type": "Linux",
      "service_type": "Nginx",
      "status": 1,
      "created_at": "2026-01-19T07:14:43Z"
    }
  ],
  "total": 3,
  "page": 1,
  "size": 20
}
```

#### GET /api/alerts
获取告警列表

**参数:**
| 参数 | 类型 | 说明 |
|------|------|------|
| severity | string | 严重程度过滤 |
| status | int | 状态过滤 |
| action | string | 动作过滤 |
| source_ip | string | 来源 IP 过滤 |
| start_time | string | 开始时间 |
| end_time | string | 结束时间 |

**响应示例:**
```json
{
  "data": [
    {
      "id": 1,
      "sid": "2000001",
      "source_ip": "192.168.1.100",
      "severity": "high",
      "signature_name": "SQL Injection",
      "status": 0,
      "timestamp": "2026-01-19T07:14:43Z"
    }
  ],
  "total": 1,
  "page": 1,
  "size": 20
}
```

#### GET /api/strategies
获取策略列表

**参数:**
| 参数 | 类型 | 说明 |
|------|------|------|
| enabled | int | 启用状态过滤 |

**响应示例:**
```json
{
  "data": [
    {
      "id": 1,
      "s_id": "",
      "target_file": "/etc/nginx/sites-available/default",
      "match_regex": "location /admin",
      "replace_content": "...",
      "description": "限制 admin 访问",
      "enabled": 1
    }
  ],
  "total": 2,
  "page": 1,
  "size": 20
}
```

#### POST /api/strategies
创建新策略

**请求体:**
```json
{
  "target_file": "/etc/nginx/sites-available/default",
  "match_regex": "location /admin",
  "replace_content": "location /admin\n    allow 10.0.0.0/8;\n    deny all;",
  "description": "限制 admin 访问",
  "enabled": true
}
```

#### POST /api/block
手动封禁 IP

**请求体:**
```json
{
  "ip": "192.168.1.100",
  "reason": "检测到恶意扫描行为",
  "expires": 3600
}
```

**响应示例:**
```json
{
  "success": true,
  "message": "Block command sent for IP 192.168.1.100"
}
```

#### GET /api/logs
获取操作日志

**参数:**

## 平台兼容与本地编译说明

- 由于 IPTables 实现为 Linux 平台（`internal/agent/executor/iptables_linux.go`），在 macOS 上为了本地开发和测试已增加了 `internal/agent/executor/iptables_stub.go`。
- 如果在 Linux 生产环境运行，请确保 `iptables` 可用并且 Agent 可以执行 `iptables` 命令（必要权限）。
- 本地测试时命令会返回 `"ip blocking is not supported on this platform"`，不会实际修改防火墙。

## 状态确认

- `go test ./...`：通过
- Master 服务可访问 Web 页面：`GET /` (Dashboard)
- gRPC 服务可接收 Agent 上报：`ReportAlert`
- 自动封禁：`block` 命令会广播给所有在线 Agent
- 策略修复：`PATCH_CONFIG` 支持 piping 逻辑与回滚
| 参数 | 类型 | 说明 |
|------|------|------|
| page | int | 页码 (默认 1) |
| page_size | int | 每页数量 (默认 50) |

**响应示例:**
```json
{
  "data": [
    {
      "id": 1,
      "command_id": "cmd-001",
      "command_type": "block_ip",
      "alert_id": "alert-001",
      "result": 0,
      "created_at": "2026-01-19T07:14:43Z"
    }
  ],
  "total": 10,
  "page": 1,
  "size": 50
}
```

#### GET /health
健康检查

**响应示例:**
```json
{
  "status": "ok",
  "timestamp": 1705641283000
}
```

## Docker 部署

### 目录结构

```
deploy/
├── docker-compose.yaml    # Docker Compose 配置
├── Dockerfile.master      # Master 服务镜像
├── Dockerfile.agent       # Agent 服务镜像
├── init.sql              # 数据库初始化脚本
└── configs/              # 配置目录
```

### 环境变量

**Master 服务:**
| 变量 | 说明 | 默认值 |
|------|------|--------|
| DB_HOST | MySQL 主机 | mysql |
| DB_PORT | MySQL 端口 | 3306 |
| DB_USER | 数据库用户 | root |
| DB_PASSWORD | 数据库密码 | rootpassword |
| DB_NAME | 数据库名 | security |
| REDIS_HOST | Redis 主机 | redis |
| REDIS_PORT | Redis 端口 | 6379 |

**Agent 服务:**
| 变量 | 说明 | 默认值 |
|------|------|--------|
| MASTER_ADDRESS | Master 地址 | master:50051 |
| SURICATA_LOG_PATH | Suricata 日志路径 | /var/log/suricata/eve.json |
| RECONNECT_INTERVAL | 重连间隔(秒) | 5 |
| HEARTBEAT_INTERVAL | 心跳间隔(秒) | 30 |

### 监控日志

```bash
# Master 日志
docker logs dasrs-master -f

# Agent 日志
docker logs dasrs-agent -f

# MySQL 日志
docker logs dasrs-mysql -f

# Redis 日志
docker logs dasrs-redis -f
```

### 停止服务

```bash
docker-compose down

# 删除数据卷
docker-compose down -v
```

## 开发环境

### 本地编译

```bash
# 编译 Master
go build -o master ./cmd/master

# 编译 Agent
go build -o agent ./cmd/agent
```

### 运行测试

```bash
# 运行所有测试
go test ./...

# 运行指定包测试
go test ./internal/...
```

### 添加 Suricata 测试日志

```bash
# 创建测试日志目录
mkdir -p suricata_logs

# 添加测试日志 (EVE JSON 格式)
cat > suricata_logs/eve.json << 'EOF'
{"timestamp":"2026-01-19T12:00:00.000000+0800","flow_id":12345,"event_type":"alert","alert":{"action":"allowed","gid":1,"signature_id":2000001,"rev":1,"signature":"SQL Injection","category":"Attempted Information Leak","severity":2},"src_ip":"192.168.1.100","src_port":12345,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP"}
EOF
```

## 故障排查

### 常见问题

1. **端口冲突**
   - MySQL 3306 端口被占用，修改 `docker-compose.yaml` 中的端口映射

2. **Agent 无法连接 Master**
   - 检查 Master 服务是否正常运行
   - 检查网络配置: `docker network ls`

3. **数据库连接失败**
   - 等待 MySQL 健康检查完成
   - 查看 MySQL 日志: `docker logs dasrs-mysql`

4. **模板文件加载失败**
   - 确保 `templates/index.html` 存在
   - 检查 volume 挂载是否正确

### 查看服务状态

```bash
# 检查容器运行状态
docker ps -a

# 检查容器健康状态
docker inspect dasrs-master | jq '.[0].State.Health'
```

## 架构说明

### 组件

```
┌─────────────┐     gRPC      ┌─────────────┐
│   Agent     │◄─────────────►│   Master    │
│  (客户端)    │  双向流通信   │  (服务端)    │
└──────┬──────┘               └──────┬──────┘
       │                             │
       │ Suricata                    │ MySQL
       ▼                             ▼
┌─────────────┐               ┌─────────────┐
│   EVE JSON  │               │   Database  │
└─────────────┘               └─────────────┘
                                    │
                                    │ Redis
                                    ▼
                             ┌─────────────┐
                             │    Cache    │
                             └─────────────┘
```

### 风险评分算法

系统使用情报引擎进行风险评估：

1. **基础分** (Base Score)
   - critical: 100
   - high: 75
   - medium: 50
   - low: 25
   - unknown: 0

2. **时序分析** (Time Series Score)
   - 时间窗口内告警频率加权
   - 频繁触发增加风险分

3. **决策阈值**
   - block_threshold: 50 (封禁)
   - repair_threshold: 80 (修复)

## License

MIT License

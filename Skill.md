# Skill: 构建 DASRS (分布式情报驱动应急响应系统)

> **角色设定:** 资深 Go 后端架构师 & 网络安全工程师 **任务目标:** 构建一个基于 Master-Agent 架构的自动化威胁响应系统。 **版本:** 1.0.0

## 1. 项目概览 (Project Overview)

**DASRS** 是一个分布式自动化防御系统：

- **Agent (边缘端):** 部署在业务服务器。负责实时采集 Suricata 日志，执行 Nginx 配置文件的热修复，以及管理 iptables 防火墙。
- **Master (中枢端):** 负责多维情报分析（信誉评分、资产上下文、时序分析），并基于 gRPC 双向流下发防御指令。

## 2. 技术栈规范 (Technical Standards)

- **语言:** Go (Golang) 1.21+
- **通信协议:** gRPC + Protocol Buffers v3 (双向流 Bidirectional Streaming)
- **API 框架:** Gin (仅用于 Master 管理接口)
- **数据存储:** MySQL 8.0 (持久化), Redis 7.0 (消息队列/缓存)
- **运行环境:** Linux (Ubuntu 20.04+), Docker & Docker Compose
- **核心依赖库:**
  - `google.golang.org/grpc`: RPC 通信
  - `gorm.io/gorm`: ORM 数据库操作
  - `github.com/hpcloud/tail`: 日志文件监控
  - `github.com/go-redis/redis/v8`: Redis 客户端

## 3. 目录结构规范 (Directory Structure Schema)

请严格遵守以下目录结构进行初始化：

Plaintext

```
security-response-system/
├── cmd/
│   ├── master/             # 入口：Master 服务
│   └── agent/              # 入口：Agent 服务
├── configs/                # YAML 配置文件
├── deploy/                 # Docker-compose & Dockerfiles
├── internal/
│   ├── common/             # 公共库 (Logger, Utils)
│   ├── proto/              # 生成的 PB 代码 (勿手动修改)
│   ├── master/
│   │   ├── api/            # Gin HTTP Handlers
│   │   ├── core/           # 核心：情报与决策引擎
│   │   ├── grpc/           # gRPC Server 实现
│   │   ├── model/          # 数据库 GORM 模型
│   │   └── service/        # 业务逻辑层
│   └── agent/
│       ├── collector/      # Suricata 日志采集器
│       ├── executor/       # 执行器 (Nginx Patcher & Iptables)
│       └── client/         # gRPC Client & Stream 处理
├── pkg/                    # 可复用包
├── proto/                  # .proto 定义文件
├── go.mod
└── go.sum
```

## 4. 分阶段构建指令 (Implementation Phases)

### 阶段一：基础设施与协议定义 (Infrastructure)

**目标:** 建立通信契约与开发环境。

1. **初始化:** 执行 `go mod init security-response-system`。
2. **Proto 定义 (`proto/security.proto`):**
   - `SendHeartbeat`: Unary RPC (Agent -> Master)。上报 Hostname, IP, CPU/Mem 负载。
   - `ReportAlert`: Unary RPC (Agent -> Master)。上报威胁日志 (`sid`, `payload`, `source_ip`, `asset_info`)。
   - `CommandStream`: 双向流 (Bidirectional Stream)。Master 用于实时推送 `BlockIP` 或 `PatchConfig` 指令。
3. **代码生成:** 生成 Go 代码至 `internal/proto` 目录。
4. **环境准备:** 编写 `deploy/docker-compose.yaml`，包含 MySQL (DB: `security`) 和 Redis。

### 阶段二：Agent 端核心功能 (The Agent - 眼与手)

**目标:** 实现日志采集与安全的系统命令执行。

1. **采集器 (Collector):** 使用 `hpcloud/tail` 监控 `/var/log/suricata/eve.json`。仅过滤 `event_type: alert` 的日志，转换为 Protobuf 结构体。
2. **阻断器 (Blocker):** 封装 `iptables` 命令，实现 `BlockIP(ip)` 和 `UnblockIP(ip)`。
3. **配置热修复器 (Config Patcher - 重点):** 在 `internal/agent/executor` 中实现 `PatchNginxConfig`。
   - **逻辑:** 必须严格遵循 *第5节：关键算法逻辑* 中的安全流程。

### 阶段三：Master 端决策引擎 (The Master - 大脑)

**目标:** 实现情报分析引擎与指令分发。

1. **数据模型 (MySQL/Gorm):**
   - `Asset`: 资产表 (IP, 操作系统类型, 服务类型如 Nginx/IIS)。
   - `Strategy`: 策略表 (Sid, 目标文件路径, 正则表达式, 替换内容)。
   - `AlertLog` & `OperationLog`: 日志记录。
2. **情报引擎 (Intelligence Engine):**
   - **输入:** Suricata 告警等级。
   - **上下文过滤 (Context):** 如果告警攻击类型是 "IIS" 但资产库显示该 IP 运行 "Nginx" -> 评分归 0 (忽略误报)。
   - **时序分析 (Time-Series):** 查询 Redis 中该 SourceIP 过去 1 分钟的频次。如果 > 10 次 -> 评分 * 1.5。
   - **决策:** 如果最终评分 > 阈值 (如 80) -> 查询 `Strategy` 表 -> 推送修复指令；否则 -> 推送封禁指令。
3. **gRPC Server:** 处理连接流，维护 `AgentID` 到 `StreamServer` 的映射，以便精准推送。

### 阶段四：Web API 与集成 (API & Integration)

**目标:** 外部管控与自动化构建。

1. **REST API (Gin):**
   - `GET /api/agents`: 获取在线 Agent 列表。
   - `GET /api/alerts`: 获取历史告警。
   - `POST /api/block`: 手动下发封禁指令。
2. **Makefile:** 包含 `proto-gen`, `build`, `run` 等脚本。

## 5. 关键算法逻辑 (Critical Algorithms)

### Nginx 配置文件安全热修复

**约束:** 严禁破坏生产环境的 Web 服务。所有文件修改必须遵循 **原子性 备份-验证-重载** 循环。

Go

```
// internal/agent/executor 参考逻辑
func SafePatch(filePath, matchRegex, replaceContent string) error {
    backupPath := fmt.Sprintf("%s.bak.%d", filePath, time.Now().Unix())

    // 1. 创建备份 (Create Backup)
    if err := copyFile(filePath, backupPath); err != nil {
        return fmt.Errorf("backup failed: %w", err)
    }

    // 2. 修改文件 (Read -> Regex Replace -> Write)
    // ... 具体实现略 ...

    // 3. 语法验证 (Verify Syntax - 关键步骤)
    // 使用 nginx -t -c 指定配置文件进行检查
    cmd := exec.Command("nginx", "-t", "-c", filePath)
    if err := cmd.Run(); err != nil {
        // 4. 失败回滚 (ROLLBACK on Failure)
        copyFile(backupPath, filePath) // 恢复原文件
        return fmt.Errorf("syntax check failed, rolled back: %v", err)
    }

    // 5. 应用变更 (Apply Changes)
    if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
         return fmt.Errorf("reload failed: %v", err)
    }
    
    return nil
}
```

## 6. 验收清单 (Verification Checklist)

- [ ] Protobuf 定义是否兼容 gRPC v3 标准？
- [ ] Agent 是否具备断线重连 (Reconnect) 机制？
- [ ] Nginx Patcher 是否在 Reload 之前强制执行了 `nginx -t`？
- [ ] Master 是否正确实现了基于资产类型 (Asset Context) 的误报过滤？
- [ ] Redis 中的计数器 Key 是否设置了正确的过期时间？
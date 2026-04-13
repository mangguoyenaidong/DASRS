# Skill: 构建 DASRS (分布式情报驱动应急响应系统)

> **角色设定:** 资深 Go 后端架构师 & 网络安全工程师 **任务目标:** 构建一个基于 Master-Agent 架构的自动化威胁响应系统。 **版本:** 1.2.0

## 1. 项目概览 (Project Overview)

**DASRS** 是一个分布式自动化防御系统：

- **Agent (边缘端):** 部署在业务服务器。负责实时采集 Suricata 日志，执行 Nginx 配置文件的热修复，以及管理 iptables 防火墙。
- **Master (中枢端):** 负责多维情报分析（信誉评分、资产上下文、时序分析），并基于 gRPC 双向流下发防御指令，提供 Web 可视化管理后台。

## 2. 技术栈规范 (Technical Standards)

- **语言:** Go (Golang) 1.25+
- **通信协议:** gRPC + Protocol Buffers v3 (双向流 Bidirectional Streaming)
- **API 框架:** Gin (Master 管理接口与 Web 渲染)
- **数据存储:** MySQL 8.0 (持久化策略、资产、审计日志), Redis 7.0 (时序分析计数器)
- **运行环境:** Linux (Ubuntu 20.04+), Docker & Docker Compose
- **辅助工具:** Python 3 (配置助手 `configure.py`)

## 3. 目录结构规范 (Directory Structure Schema)

Plaintext
```
DASRS/
├── cmd/
│   ├── master/             # 入口：Master 服务 (gRPC Server + HTTP API)
│   └── agent/              # 入口：Agent 服务 (gRPC Client + Collector)
├── configs/                # YAML 配置文件 (master/agent 分离)
├── deploy/                 # Docker-compose 部署方案
├── internal/
│   ├── common/             # 公共库 (Logger, UUID, Utils)
│   ├── proto/              # 生成的 PB 代码
│   ├── master/
│   │   ├── api/            # Gin Handlers (含白名单、策略管理)
│   │   ├── core/           # 核心：情报引擎 (评分、误报过滤、时序分析)
│   │   ├── grpc/           # gRPC Server 实现 (指令下发队列)
│   │   ├── model/          # GORM 模型与数据库迁移
│   └── agent/
│       ├── collector/      # Suricata 日志实时采集 (Tail 模式)
│       ├── executor/       # 执行器 (iptables 阻断 & 配置文件原子热修复)
├── templates/              # Web 后台 HTML 模板
├── configure.py            # 交互式环境配置脚本
├── go.mod
└── Skill.md
```

## 4. 核心功能描述

### 4.1 智能情报引擎 (Intelligence Engine)
- **多维评分**: 结合 Suricata 告警等级（基础分）与告警频次（时序分）。
- **误报过滤**: 自动比对资产指纹（如：攻击目标是 IIS 但实际运行 Nginx 则判定为误报）。
- **白名单保护**: 强制保护 Master 节点、本地回环及数据库定义的动态白名单 IP，防止误封。

### 4.2 原子性配置修复 (Config Patcher)
- **安全保障**: 遵循 `备份 -> 修改 -> 语法检查 (nginx -t) -> 重载 (reload) -> 失败回滚` 流程。
- **扩展性**: 通过接口支持 Nginx、Apache 等多种中间件的配置热修复。

### 4.3 实时可视化后台
- **威胁地图**: 展示实时告警趋势与风险分布。
- **报文审计**: 支持原始 Payload 的 Base64 解码、Text 展示与 Hex 十六进制审计，便于人工判定。

## 5. 关键算法逻辑

### 风险评分加权公式
```text
FinalScore = BaseScore(Severity) + TimeSeriesBonus(Freq)
- BaseScore: Critical(100), High(75), Medium(50), Low(25)
- TimeSeriesBonus: 频率超过阈值则 +25/50 分
- Whitelist: 如果 IP 在白名单，则 FinalScore = 0 (强制忽略)
```

## 6. 当前进展

- [x] **v1.0.0**: 完成基础 Master-Agent gRPC 通信与告警上报。
- [x] **v1.1.0**: 实现 Nginx 配置文件原子性热修复与 iptables 阻断执行器。
- [x] **v1.2.0**: 
    - [x] 引入 **动态 IP 白名单** 管理系统。
    - [x] 开发 **交互式配置助手** (`configure.py`)。
    - [x] 升级 Web 审计后台，支持 **Hex 原始报文审计** 与批量操作。
    - [x] 完善情报引擎的 **告警关联分析 (Correlation)** 逻辑。

## 7. 运行指引

1. **环境初始化**: 执行 `python3 configure.py` 按提示配置数据库与 Master IP。
2. **启动依赖**: `cd deploy && docker-compose up -d`。
3. **启动 Master**: `go run ./cmd/master` (默认监听 8080 与 50051)。
4. **启动 Agent**: `go run ./cmd/agent --config configs/agent.yaml`。
5. **访问后台**: 浏览器打开 `http://<Master_IP>:8080`。

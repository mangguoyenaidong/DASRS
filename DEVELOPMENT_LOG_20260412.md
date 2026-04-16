# DASRS 开发与部署日志 (2026-04-12)

> 注：本文件是阶段性开发记录，不作为实时部署真相源。启动命令、访问地址和配置项请优先以 `README.md`、`docs/USAGE.md` 及当前配置文件为准。

## 1. 项目当前状态 (Current Status)
- **架构**: Master-Agent (gRPC 双向流)
- **核心功能**: 实时告警上报、自动化 IP 封禁、Nginx 配置热修复、Web 管理后台。
- **最新进展**: 成功打通多机实机部署，实现了 Web 动态白名单管理，并增加了自动化配置脚本。

## 2. 部署与环境调试 (Troubleshooting)

### 2.1 Agent 连接 Master 失败
- **现象**: Agent 报错 `dns: A record lookup error: lookup master`。
- **原因**: 默认配置指向主机名 `master`，在非 Docker 环境下无法解析。
- **解决**: 修改 `configs/agent.yaml` 中的 `master_address` 为当前环境下 Master 的实际可达地址，例如 `<master-ip>:50051`。
- **注意**: 启动 Agent 时需明确指定配置文件：`go run ./cmd/agent/main.go --config configs/agent.yaml`。

### 2.2 IP 自动封禁问题
- **现象**: 源 IP `192.168.41.1` 被系统自动封禁。
- **原因**: 
  - 虽然告警等级为 `low` (25分)，但触发频率超过了 `time_window` (60s) 内的限制。
  - 时序分析引擎自动加了 25 分，总分达到 50 分，触碰了 `block_threshold`。
- **解决**: 实现了 IP 白名单机制，强制将受信任 IP 的风险评分归 0。

### 2.3 Master 进程关闭异常
- **现象**: `Ctrl+C` 无法终止进程，端口 8080 依然被占用。
- **原因**: 进程可能因处理大量 HTTP 长连接（Web 自动刷新）而阻塞。
- **解决**: 使用 `sudo lsof -i :8080` 找到 PID，并执行 `kill -9 <PID>` 强制终止。

## 3. 新增功能模块 (New Features)

### 3.1 IP 白名单管理 (Whitelist)
- **后端**: 
  - 新增 `whitelist_ips` 数据库表。
  - 升级 `IntelligenceEngine` 逻辑：`isWhitelisted` 同时检查静态配置和数据库动态记录。
- **API**: 增加 `GET/POST/DELETE /api/whitelist` 接口。
- **Web 端**: 在管理控制台左侧新增“白名单”菜单，支持动态增删 IP。

### 3.3 系统稳定性修复 (Bug Fixes)
- **审计功能修复**: 解决了由于 Base64 非标准字符解码导致 JS 崩溃的问题。增加了 `try-catch` 保护和即时加载反馈。
- **资产去重逻辑**: 修正了 `registerAgent` 接口，强制以 IP 作为资产唯一键，彻底解决了同一 Agent 重复出现在列表中的问题。
- **封禁状态同步**: 优化了解封逻辑，现在解封 IP 会同步更新告警日志状态，确保“生效名单”实时准确。

## 4. 关键文件清单 (Key Files)
- `configs/config.yaml`: Master 全局配置（含静态白名单）。
- `configs/agent.yaml`: Agent 专属配置。
- `internal/master/core/engine.go`: 核心分析引擎逻辑。
- `internal/master/api/server.go`: Web API 路由与处理器。
- `templates/index.html`: 管理后台前端页面。

## 5. 后续操作建议
1. **启动 Master**: `go run ./cmd/master/main.go`
2. **启动 Agent**: `go run ./cmd/agent/main.go --config configs/agent.yaml`
3. **管理后台**: `http://<master-host>:8080/`
4. **代码状态**: 请以当前 Git 仓库状态与远端分支为准，不在本文档中固化说明。

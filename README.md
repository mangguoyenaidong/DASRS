# DASRS

DASRS (Distributed Intelligence-Driven Emergency Response System) 是一个基于 Master-Agent 架构的分布式安全响应系统，用于采集 Suricata 告警、执行风险分析，并联动 Agent 完成 IP 封禁与配置修复。

## 项目能力

- 实时采集 Suricata EVE JSON 告警
- 基于严重级别、时序频率和白名单的风险分析
- 通过 gRPC 向在线 Agent 下发封禁/解封指令
- 支持 Nginx 配置热修复与回滚
- 提供 Web 管理后台、告警审计和白名单管理

## 技术栈

- Go 1.25+
- Gin
- gRPC + Protocol Buffers
- MySQL 8.0
- Redis 7.0
- Python 3 (`configure.py` 依赖 `ruamel.yaml`)
- Docker / Docker Compose

## 仓库结构

```text
cmd/                 程序入口
configs/             Master/Agent 配置
deploy/              Docker 部署文件
docs/                项目使用文档
internal/            核心业务代码
proto/               protobuf 定义
templates/           Web 管理后台模板
configure.py         交互式配置助手
```

## 快速开始

### 1. 准备依赖

- Docker / Docker Compose
- Go 1.25+
- Python 3

如需使用交互式配置助手，先安装：

```bash
pip install ruamel.yaml
```

### 2. 配置系统

推荐先运行：

```bash
python3 configure.py
```

也可以手动修改：

- `configs/config.yaml`：Master、数据库、Redis、白名单等配置
- `configs/agent.yaml`：Agent 连接地址、Suricata 日志路径、`monitor_ip` 等配置

### 3. 启动基础设施

```bash
cd deploy
docker-compose up -d
```

### 4. 启动服务

```bash
go run ./cmd/master --config configs/config.yaml
go run ./cmd/agent --config configs/agent.yaml
```

### 5. 访问后台

默认地址：

- `http://localhost:8080`

如果 Master 部署在远程机器，请改用对应机器的实际 IP 或域名访问。

## 常用文档

- [项目使用文档](D:/file/DASRS/docs/USAGE.md)
- [开发与部署日志](D:/file/DASRS/DEVELOPMENT_LOG_20260412.md)
- [项目技能说明](D:/file/DASRS/Skill.md)

## 说明

- `configs/config.yaml` 中示例 `master:50051` 仅适用于 Docker 内部网络。
- 非 Docker 或跨主机部署时，`configs/agent.yaml` 中的 `master_address` 必须改为 Master 的实际可达地址。
- 文档中的 IP、路径和端口均以“示例配置”解释为主，实际部署请以当前环境为准。

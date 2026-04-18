# DASRS

DASRS（Distributed Intelligence-Driven Emergency Response System）是一个基于 `Master-Agent` 架构的分布式安全检测与响应系统，用于采集 `Suricata` 告警、进行风险评分，并联动 Agent 执行封禁或修复动作。

## 项目能力

- 实时采集 `Suricata EVE JSON` 告警
- 基于严重等级、时序频率、白名单和目标服务上下文的风险评分
- 通过 `gRPC` 向在线 Agent 下发封禁 / 解封指令
- 支持部分节点侧修复动作与回滚
- 提供 Web 管理后台、审计日志、白名单与策略管理
- 支持节点本地服务发现与轻量资产指纹
- 支持 AI 候选规则生成、人工修订、测试后下发
- 支持 AI 告警研判、证据提取和运维建议生成

## 技术栈

- Go 1.25+
- Gin
- gRPC + Protocol Buffers
- MySQL 8.0
- Redis 7.0
- Python 3
- Docker / Docker Compose

## 仓库结构

```text
cmd/                 程序入口
configs/             Master / Agent 配置
deploy/              Docker 部署文件
docs/                使用文档
internal/            核心业务代码
proto/               Protobuf 定义
templates/           Web 管理后台模板
configure.py         配置辅助脚本
```

## 快速开始

### 1. 准备依赖

- Docker / Docker Compose
- Go 1.25+
- Python 3

如需使用配置辅助脚本：

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

- 默认地址：`http://localhost:8080`
- 远程部署时请改为 Master 实际 IP 或域名

## 常用文档

- [项目使用文档](D:/file/DASRS/docs/USAGE.md)
- [开发与部署日志](D:/file/DASRS/DEVELOPMENT_LOG_20260412.md)
- [项目技能说明](D:/file/DASRS/Skill.md)

## 2026-04 Recent Updates

本轮更新主要集中在“AI 联动闭环”“演示模式”和“资产感知增强”三部分。

### 0. AI 联动闭环

- 新增 `DeepSeek` 接入，可用于：
  - 漏洞语义到 Suricata 候选规则生成
  - 告警语义研判与处置建议
- 新增 AI 工作台，支持：
  - `生成 -> 人工修订 -> 测试 -> 下发` 四步流程
  - 候选规则人工编辑
  - `Master` 静态测试与 `Agent` 动态测试
  - 告警数据库 ID 触发 AI 研判
- AI 告警研判结果新增结构化字段：
  - `impact_scope`
  - `evidence_points`
  - `suspicious_path`
  - `suspicious_params`
  - `command_fragments`
  - `operator_advice`

### 0.1 Demo Mode 演示模式

为了比赛演示时更容易出现自动封禁/修复效果，新增了独立的演示模式配置：

```yaml
master:
  intelligence:
    demo_mode: false
    demo_block_threshold: 40
    demo_repair_threshold: 65
    demo_exploit_bonus: 15
```

说明：

- 默认 `demo_mode: false`，系统仍使用原始生产阈值
- 开启后只会放宽演示阈值，不会改动默认配置逻辑
- 对明显利用类告警会追加少量演示分，便于现场更稳定地展示 `block / repair`
- Web 的 AI 工作台会直接显示当前是否开启 `Demo Mode`

### 1. Agent 本地服务发现

- Agent 新增 Linux 本地服务发现能力
- 启动后会先扫描一次本地监听服务，后续按周期继续上报
- 当前可上报的信息包括：
  - 协议
  - 监听地址
  - 端口
  - 进程名
  - PID
  - 推断服务类型

新增 Agent 配置项：

- `master_http_address`
- `agent_name`
- `service_scan_interval`

### 2. 资产节点详情页

- 在资产页点击节点状态后，可查看节点详情
- 节点详情页可展示：
  - 节点基础信息
  - 最新服务清单
  - 兜底服务信息

### 3. 轻量资产指纹

- 服务发现结果会同步回写到资产相关记录
- 当前可更新：
  - `os_type`
  - `service_type`
  - 节点 `service_inventory`
- Java 服务可进一步识别为：
  - `tomcat`
  - `jenkins`
  - `nacos`
  - `spring-boot`
  - `elasticsearch`
  - `kafka`

### 4. 告警评分更新

基础分已调整为：

- `critical = 80`
- `high = 60`
- `medium = 35`
- `low = 15`

当前评分模型：

```text
final score = base score + target-service context score + time-series score
```

其中目标服务上下文分为：

- 与目标服务明显匹配：`+20`
- 与目标服务明显不匹配：`-20`
- 无法判断：`0`

这意味着系统现在不仅看告警等级，也会结合目标主机真实暴露的服务来修正评分，从而减少误报并提高自动处置准确性。

## 说明

- `configs/config.yaml` 中示例的 `master:50051` 仅适用于 Docker 内部网络
- 非 Docker 或跨主机部署时，`configs/agent.yaml` 中的 `master_address` 必须改为 Master 的实际可达地址
- 文档中的 IP、路径和端口均为示例，请以当前环境为准

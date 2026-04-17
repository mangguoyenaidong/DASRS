# DASRS 开发与部署日志 (2026-04-12)

> 说明：本文档用于记录阶段性开发结果与本轮关键改动。运行命令、访问地址和最终配置说明请优先以 `README.md`、`docs/USAGE.md` 与当前配置文件为准。

## 1. 项目阶段状态

- 架构：`Master-Agent` 分布式联动架构，Master 负责分析与决策，Agent 负责节点侧采集与执行。
- 已具备能力：Suricata 告警采集、风险评分、自动封禁、Web 管理后台、白名单管理、策略管理、部分自动化修复。
- 当前阶段重点：从“检测与响应”继续推进到“资产感知 + 上下文评分”。

## 2. 早期问题与处理

### 2.1 Agent 无法连接 Master

- 现象：Agent 报错 `lookup master`。
- 原因：默认配置里的 `master:50051` 仅适用于容器内部网络。
- 处理：将 `configs/agent.yaml` 中的 `master_address` 改为实际可达地址，如 `<master-ip>:50051`。

### 2.2 低危告警也触发自动封禁

- 现象：部分 `low` 级告警在高频出现时被自动封禁。
- 原因：旧版评分中基础分较高，再叠加时序分后容易越过封禁阈值。
- 处理：后续已降低基础分，并增加目标服务上下文评分，以减少误触发。

### 2.3 后台与资产状态同步不稳定

- 处理过的问题包括：
  - 动态白名单管理接入数据库
  - Agent 注册去重
  - 解封后状态同步
  - 审计详情展示稳定性

## 3. 本轮新增能力

### 3.1 资产节点详情

- 资产页中点击节点状态后，可打开节点详情视图。
- 详情页可展示：
  - 节点基础信息
  - 节点最新服务清单
  - 若暂无完整扫描结果，则展示可用的资产服务兜底信息

### 3.2 Agent 本地服务发现

- Agent 新增 Linux 本地服务发现能力。
- 启动后先执行一次扫描，后续按周期继续上报。
- 当前可采集字段包括：
  - 协议
  - 监听地址
  - 端口
  - 进程名
  - PID
  - 推断服务类型

### 3.3 轻量资产指纹

- 本地服务发现结果会同步写回资产相关记录。
- 当前可回填的信息包括：
  - `os_type`
  - `service_type`
  - 节点 `service_inventory`
- Java 进程不再统一只显示为 `java-service`，目前可进一步识别：
  - `tomcat`
  - `jenkins`
  - `nacos`
  - `spring-boot`
  - `elasticsearch`
  - `kafka`

### 3.4 评分机制调整

- 基础分从较激进的配置调整为更保守的配置：
  - `critical = 80`
  - `high = 60`
  - `medium = 35`
  - `low = 15`
- 新增目标服务上下文评分：
  - 与目标服务明显匹配：`+20`
  - 与目标服务明显不匹配：`-20`
  - 无法判断：`0`
- 当前评分公式为：

```text
final score = base score + target-service context score + time-series score
```

这意味着系统不再只按告警等级做处置，而是会结合目标机器真实暴露的服务来修正风险值。

### 3.5 联动闭环验证

- 已完成一次完整联动验证：
  - Suricata 成功检测攻击流量
  - Agent 成功采集并上报告警
  - Master 完成评分与动作决策
  - Agent 成功执行自动封禁

## 4. 涉及的关键文件

- `cmd/agent/agent.go`
- `cmd/agent/config.go`
- `internal/agent/client/grpc.go`
- `internal/agent/collector/suricata.go`
- `internal/agent/discovery/service_scan_linux.go`
- `internal/master/api/server.go`
- `internal/master/core/engine.go`
- `internal/master/grpc/server.go`
- `internal/master/model/models.go`
- `templates/index.html`

## 5. 验证结果

- 回归验证命令：

```bash
go test ./...
```

- 本轮相关测试已通过。

## 6. 后续建议

1. 继续扩展轻量资产指纹，把更多常见中间件从泛化服务中识别出来。
2. 将服务指纹进一步用于误报抑制、策略推荐与可视化展示。
3. 后续如需进入论文或答辩材料，可将本轮改动整理成“资产感知增强”和“上下文评分优化”两个模块单独说明。

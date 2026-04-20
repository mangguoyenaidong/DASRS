# DASRS

DASRS is a distributed security detection and response system built on a `Master-Agent` architecture. It ingests `Suricata` alerts, scores risk with asset context and time-series signals, and coordinates response actions such as block, unblock, patch, and AI-assisted rule generation.

## Highlights

- Real-time collection of `Suricata EVE JSON` alerts
- Asset-aware alert scoring with whitelist and burst-frequency correction
- `gRPC` command delivery from Master to online Agents
- Web console for assets, alerts, blocking, strategies, logs, and AI workflows
- AI-powered candidate rule generation with manual review, testing, and deployment
- AI alert analysis with structured evidence extraction and operator guidance
- Demo mode thresholds for competition and showcase scenarios

## Architecture

```text
Suricata -> Agent -> gRPC -> Master -> MySQL/Redis -> Web Console
                           |
                           +-> AI rule generation / AI alert analysis
                           +-> block / unblock / patch / deploy rule
```

## Main Components

- `cmd/master`
  Master startup entry
- `cmd/agent`
  Agent startup entry
- `internal/master`
  scoring engine, HTTP API, gRPC server, AI services
- `internal/agent`
  Suricata collector, local service discovery, executors
- `templates/index.html`
  Web console
- `configs/config.yaml`
  Master configuration
- `configs/agent.yaml`
  Agent configuration

## Core Features

### Alert detection and response

- Collect `alert` events from `eve.json`
- Score alerts by:
  - severity
  - target asset/service context
  - time-window frequency
  - whitelist status
- Trigger actions:
  - `ignore`
  - `block`
  - `repair`

### AI workflow

- DeepSeek-based rule generation
- Candidate rule manual editing in Web UI
- Static validation on Master
- Dynamic testing on Agent
- Deployment to managed Suricata rule file
- AI alert analysis with:
  - `summary`
  - `attack_type`
  - `risk_reason`
  - `impact_scope`
  - `evidence_points`
  - `suspicious_path`
  - `suspicious_params`
  - `command_fragments`
  - `operator_advice`
  - `recommended_action`
  - `confidence`

### Demo mode

When `master.intelligence.demo_mode=true`, the system can use looser action thresholds and a small exploit bonus for more visible on-stage responses.

## Quick Start

### 1. Prerequisites

- Go `1.25+`
- MySQL `8.0`
- Redis `7.0`
- Docker / Docker Compose
- Python `3` for helper scripts

If you use the configuration helper:

```bash
pip install ruamel.yaml
```

### 2. Configure

Recommended:

```bash
python3 configure.py
```

Or edit manually:

- [configs/config.yaml](/D:/file/DASRS/configs/config.yaml)
- [configs/agent.yaml](/D:/file/DASRS/configs/agent.yaml)

### 3. Start infrastructure

```bash
cd deploy
docker compose up -d mysql redis
```

### 4. Start Master and Agent

```bash
go run ./cmd/master --config configs/config.yaml
go run ./cmd/agent --config configs/agent.yaml
```

### 5. Open the Web console

- Default: [http://localhost:8080](http://localhost:8080)
- Remote: `http://<master-host>:8080`

## Key Configuration

### Master

See [configs/config.yaml](/D:/file/DASRS/configs/config.yaml).

Important sections:

- `master.database`
- `master.redis`
- `master.intelligence`
- `master.ai`

Example AI section:

```yaml
master:
  ai:
    enabled: true
    provider: "deepseek"
    api:
      base_url: "https://api.deepseek.com"
      api_key: "your_key"
      model: "deepseek-chat"
      timeout_seconds: 30
```

### Agent

See [configs/agent.yaml](/D:/file/DASRS/configs/agent.yaml).

Important fields:

- `agent.master_address`
- `agent.suricata_log_path`
- `agent.suricata_rule_path`
- `agent.suricata_reload_command`
- `agent.suricata_test_command`
- `agent.monitor_ip`

Example Agent test command:

```yaml
agent:
  suricata_test_command: "suricata -T -c /etc/suricata/suricata.yaml -S {{RULE_FILE}} -l {{TMP_DIR}}"
```

## Web Console Pages

- Dashboard
- Assets
- Alerts
- Block Control
- Strategies
- Whitelist
- Logs
- AI Workflow
- AI Settings

### AI Settings page

The dedicated AI settings page supports editing:

- AI enable/disable
- API key
- model
- base URL
- rule-generation prompts
- alert-analysis prompts
- demo mode parameters

## AI Rule Workflow

Recommended workflow:

1. Open `AI Workflow`
2. Submit `CVE`, `PoC`, or vulnerability description
3. Generate candidate rule
4. Review or manually edit the rule
5. Test it on Master or Agent
6. Deploy it after test passes

If rule generation fails with:

```text
no valid matchers generated for candidate rule
```

it usually means the model returned no usable `matchers`, or used unsupported matcher types. Supported matcher types are only:

- `content`
- `pcre`

## Alert Troubleshooting

If you send traffic but the Web console does not show a new alert, verify the chain in this order:

1. Traffic reaches the target host

```bash
sudo tcpdump -ni any host <src_ip> and host <dst_ip>
```

2. Suricata writes an `alert` event to `eve.json`

```bash
tail -f /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"'
```

3. Agent reports the alert successfully

Look for:

```text
Alert reported successfully, Master ID: ...
```

4. Web page filters are cleared

The most common root cause is not the Web UI. It is usually:

- no matching Suricata rule
- Suricata rule load failure
- `eve.json` path mismatch
- Agent scope filtering

For detailed Suricata troubleshooting, see [docs/SURICATA_RULES.md](/D:/file/DASRS/docs/SURICATA_RULES.md).

## Documents

- [Usage Guide](/D:/file/DASRS/docs/USAGE.md)
- [Suricata Rule Guide](/D:/file/DASRS/docs/SURICATA_RULES.md)


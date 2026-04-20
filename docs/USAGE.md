# DASRS Usage Guide

## 1. Overview

DASRS is a `Master-Agent` based distributed detection and response platform. It consumes Suricata alerts, scores them, persists them, and lets operators respond through a Web console. It also includes AI-assisted rule generation and AI-based alert analysis.

## 2. Runtime Requirements

- Linux recommended
- Go `1.25+`
- MySQL `8.0`
- Redis `7.0`
- Docker / Docker Compose
- Python `3`

## 3. Configuration

### 3.1 Master config

File: [configs/config.yaml](/D:/file/DASRS/configs/config.yaml)

Important fields:

- `master.host`
- `master.grpc_port`
- `master.http_port`
- `master.database.*`
- `master.redis.*`
- `master.intelligence.*`
- `master.ai.*`

### 3.2 Agent config

File: [configs/agent.yaml](/D:/file/DASRS/configs/agent.yaml)

Important fields:

- `agent.master_address`
- `agent.suricata_log_path`
- `agent.suricata_rule_path`
- `agent.suricata_reload_command`
- `agent.suricata_test_command`
- `agent.monitor_ip`
- `agent.agent_name`

Notes:

- `monitor_ip` is used to keep the Agent focused on the monitored target host.
- The collector now keeps traffic when either `src_ip` or `dest_ip` matches the monitored scope.
- If `suricata_test_command` is empty, Agent-side dynamic rule testing is unavailable.

### 3.3 AI config

Master AI configuration supports:

- enable/disable switch
- DeepSeek API key
- base URL
- model
- rule-generation prompts
- alert-analysis prompts
- test command template and success marker

You can manage these through the `AI Settings` page in the Web console.

## 4. Startup

### 4.1 Start infrastructure

```bash
cd deploy
docker compose up -d mysql redis
```

### 4.2 Start Master

```bash
go run ./cmd/master --config configs/config.yaml
```

### 4.3 Start Agent

```bash
go run ./cmd/agent --config configs/agent.yaml
```

Expected Agent startup signs:

- connected to Master
- Suricata collector started
- service inventory reported

Typical healthy log fragments:

```text
Connected to master, starting bidirectional stream...
Started Suricata collector on /var/log/suricata/eve.json
Reported 6 local services to master
```

## 5. Web Console Usage

### 5.1 Alerts

The alert page supports:

- severity filtering
- action filtering
- source/destination IP filtering
- signature search
- time-range filtering
- whitelist-only view

When troubleshooting missing alerts, clear all filters first.

### 5.2 AI Workflow

The AI workflow page supports:

- candidate Suricata rule generation
- manual rule editing
- workflow progress display
- rule testing
- rule deployment
- AI alert analysis

Recommended process:

1. Generate rule
2. Review or edit rule
3. Test rule
4. Deploy rule
5. Trigger traffic
6. Review alert and AI analysis

### 5.3 AI Settings

The AI settings page is a separate page for:

- DeepSeek API key
- base URL
- model
- rule generation prompts
- alert analysis prompts
- demo mode settings

## 6. AI Rule Generation

### 6.1 Expected model output

Candidate rule generation expects JSON with:

- `summary`
- `protocol`
- `direction`
- `attack_type`
- `message`
- `classtype`
- `target_ports`
- `matchers`

Each matcher must contain:

- `type`
- `value`

Supported matcher types:

- `content`
- `pcre`

### 6.2 Common generation failure

If you see:

```text
no valid matchers generated for candidate rule
```

the usual causes are:

- model returned an empty `matchers` array
- model returned unsupported matcher types such as `uri`, `method`, `header`, `regex`
- matcher values were empty

Use prompts that explicitly require:

- JSON only
- at least one matcher
- matcher type must be `content` or `pcre`

### 6.3 Rule testing

Master-side testing:

- static validation
- optional command template execution

Agent-side testing:

- sends test command to target Agent
- writes temporary rule file
- runs `suricata_test_command`
- reports result back to Master

Deployment is expected only after `test_status=passed`.

## 7. AI Alert Analysis

AI alert analysis consumes:

- alert metadata
- payload
- asset info
- recent alerts
- recent operations
- extracted suspicious signals

Structured output includes:

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

## 8. Demo Mode

For demos and competitions:

```yaml
master:
  intelligence:
    demo_mode: true
    demo_block_threshold: 40
    demo_repair_threshold: 65
    demo_exploit_bonus: 15
```

This mode keeps production defaults intact when disabled, and applies looser thresholds when enabled.

## 9. API Overview

### Core

- `GET /health`
- `GET /api/stats`
- `GET /api/logs`

### Alerts

- `GET /api/alerts`
- `GET /api/alerts/:id`
- `GET /api/alerts/:id/correlation`
- `GET /api/alerts/:id/ai-analysis`

### AI

- `GET /api/ai/status`
- `GET /api/ai/settings`
- `PUT /api/ai/settings`
- `POST /api/ai/rules/generate`
- `GET /api/ai/rules/:id`
- `PUT /api/ai/rules/:id`
- `POST /api/ai/rules/:id/test`
- `POST /api/ai/rules/:id/deploy`

### Agent and operations

- `GET /api/agents`
- `GET /api/agents/:id`
- `POST /api/agents/register`
- `POST /api/block`
- `POST /api/unblock`
- `POST /api/batch-block`
- `POST /api/batch-unblock`

## 10. Troubleshooting

### 10.1 Agent connected but no alerts in Web

Check in this order:

1. Traffic reaches the target

```bash
sudo tcpdump -ni any host <src_ip> and host <dst_ip>
```

2. Suricata emits `alert` events

```bash
tail -f /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"'
```

3. Agent reports alerts successfully

Look for:

```text
Alert reported successfully, Master ID: ...
```

If traffic is visible in `tcpdump` but `eve.json` has no `alert`, the issue is usually in the Suricata rule layer, not in DASRS.

### 10.2 AI alert analysis not showing

Check:

- `master.ai.enabled=true`
- API key saved correctly
- `GET /api/ai/status` shows `configuration_status=ready`

### 10.3 Agent-side AI rule test not running

Check:

- `agent.suricata_test_command` is configured
- the Agent host has Suricata installed
- the command works manually with `suricata -T`

### 10.4 Rule deploy succeeded but traffic still does not alert

Check:

- the rule file is actually loaded by Suricata
- `suricata -T` passes
- the request really matches the generated rule
- `eve.json` path matches the Agent config

For rule loading and validation details, see [docs/SURICATA_RULES.md](/D:/file/DASRS/docs/SURICATA_RULES.md).


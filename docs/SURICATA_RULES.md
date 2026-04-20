# Suricata Rule Integration Guide

This note captures the rule-loading and troubleshooting details we validated while integrating custom exploit-detection rules into DASRS.

## Scope

Use this guide when:

- you add a custom `.rules` file beside the auto-updated Suricata rules
- `suricata -T` fails before attack traffic validation
- DASRS Agent is not receiving alerts after a rule or Suricata version change

## Recommended workflow

1. Keep the auto-updated rules enabled.
2. Put custom exploit detection rules in a separate local rule file.
3. Reference that file explicitly in `suricata.yaml`.
4. Run `suricata -T` before replaying traffic or generating test traffic.
5. Confirm DASRS Agent still reads the correct `eve.json`.

Do not edit the auto-generated ruleset directly unless you are prepared for your changes to be overwritten by the next rule update.

## Rule file loading

Typical Suricata configuration:

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - local.rules
  - bc646473-fa01-4c31-8a35-c56dee3381d2.rules
```

If the custom file is not listed under `rule-files`, Suricata will not load it even if the file exists on disk.

## DASRS path checks

The project currently uses these Suricata log path conventions:

- `configs/config.yaml`: `/var/log/suricata/eve.json`
- `configs/agent.yaml`: `./suricata_logs/eve.json`

After changing Suricata packaging, container layout, or major version, verify that the actual `eve.json` output path still matches the path consumed by DASRS Agent.

## Suricata 6.x and 7.x compatibility

The current environment troubleshooting was done against Suricata `6.0.4`.

Key compatibility point:

- Suricata `6.0.4` does not support `http.request_header;`
- For Suricata `6.x`, use `http.header;`
- Suricata `7.x` supports `http.request_header;`

That means a ruleset authored for Suricata 7 may fail to load on 6.x even if the rest of the signature is valid.

## Common `suricata -T` failures

### 1. YAML parse error

Typical error:

```text
SC_ERR_CONF_YAML_ERROR(242) - Failed to parse configuration file
```

Common causes:

- inconsistent indentation
- tabs used instead of spaces
- missing `:`
- malformed list indentation under `rule-files`

### 2. Rule file not found

Typical error:

```text
SC_ERR_NO_RULES(42) - No rule files match the pattern ...
```

Check:

- the file really exists under `default-rule-path`
- the file name in `rule-files` matches exactly

### 3. Unsupported keyword on older Suricata

Typical error:

```text
SC_ERR_RULE_KEYWORD_UNKNOWN(102) - unknown rule keyword 'http.request_header'
```

Meaning:

- the rule uses a newer sticky buffer keyword than the installed Suricata version supports

### 4. Duplicate SID

Typical error:

```text
SC_ERR_DUPLICATE_SIG(176) - Duplicate signature ...
```

If two loaded rules share the same `sid`, signature loading fails.

## Validation checklist before traffic testing

Run:

```bash
suricata --build-info | head
suricata -T -c /etc/suricata/suricata.yaml
```

Then verify:

- the Suricata version matches the rule syntax you are using
- the custom rule file is listed under `rule-files`
- the file exists under `default-rule-path`
- all `sid` values are unique
- DASRS Agent is still pointed at the correct `eve.json`

Only start exploit or replay validation after the configuration test passes cleanly.

## Traffic arrived but DASRS shows no alert

If you can see the attack traffic in `tcpdump` but the Web console still shows no new alert, isolate the problem in this order:

1. Confirm the traffic really reaches the target host

```bash
sudo tcpdump -ni any host <src_ip> and host <dst_ip>
```

2. Confirm Suricata emits an `alert` event, not just `http` or `flow`

```bash
tail -f /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"'
```

3. If there is no `alert`, the issue is in Suricata detection, not in DASRS UI

Typical reasons:

- the request did not match any loaded rule
- the custom rule file was not included in `rule-files`
- the rule syntax passed loosely but did not match the actual request shape
- the test request looks malicious but still does not match the installed signatures

4. If `alert` exists in `eve.json` but not in the Web page, then check:

- Agent log for `Alert reported successfully, Master ID: ...`
- Agent `suricata_log_path`
- Agent `monitor_ip` scope
- Web page filters

### Scope filtering note

Current DASRS Agent scope filtering keeps alerts when either side of the flow matches the monitored host:

- `src_ip == monitor_ip` or `dest_ip == monitor_ip`
- `src_ip == localIP` or `dest_ip == localIP`

This is important for validating both inbound exploit traffic and outbound test traffic from the monitored node.

## Upgrade note

If you plan to upgrade from Suricata 6.x to 7.x:

- treat it as a Suricata deployment change first, not a DASRS config change first
- validate `suricata.yaml`, rule loading, and `eve.json` generation before changing DASRS Agent settings
- only update DASRS paths if the Suricata log output location actually changed

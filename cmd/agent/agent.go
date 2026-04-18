package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"security-response-system/internal/agent/client"
	"security-response-system/internal/agent/collector"
	"security-response-system/internal/agent/discovery"
	"security-response-system/internal/agent/executor"
	"security-response-system/internal/proto"
)

// Agent orchestrates local collection, execution and service reporting.
type Agent struct {
	cfg          *Config
	grpcClient   *client.Client
	collector    *collector.SuricataCollector
	scanner      discovery.Scanner
	blocker      *executor.IPBlocker
	patcher      *executor.ConfigPatcher
	ruleDeployer *executor.SuricataRuleDeployer
}

func NewAgent(
	cfg *Config,
	grpcClient *client.Client,
	collector *collector.SuricataCollector,
	scanner discovery.Scanner,
	blocker *executor.IPBlocker,
	patcher *executor.ConfigPatcher,
	ruleDeployer *executor.SuricataRuleDeployer,
) *Agent {
	return &Agent{
		cfg:          cfg,
		grpcClient:   grpcClient,
		collector:    collector,
		scanner:      scanner,
		blocker:      blocker,
		patcher:      patcher,
		ruleDeployer: ruleDeployer,
	}
}

func (a *Agent) Start() {
	log.Println("Starting agent...")

	if err := a.collector.Start(a.handleAlert); err != nil {
		log.Printf("Failed to start collector: %v", err)
	}

	a.grpcClient.Start(a.handleCommand)
	go a.reportServicesLoop()
}

func (a *Agent) Stop() {
	a.grpcClient.Stop()
	a.collector.Stop()
}

func (a *Agent) handleAlert(alert *proto.AlertReportRequest) {
	resp, err := a.grpcClient.ReportAlert(alert)
	if err != nil {
		log.Printf("Failed to report alert: %v", err)
		return
	}
	if resp != nil {
		log.Printf("Alert reported successfully, Master ID: %s", resp.AlertId)
	}
}

func (a *Agent) handleCommand(cmd *proto.CommandMessage) {
	log.Printf("Received command: %s", cmd.GetType())

	switch cmd.GetType() {
	case proto.CommandType_BLOCK_IP:
		err := a.blocker.BlockIP(cmd.GetTargetIp())
		if err != nil {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, err.Error())
		} else {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), true, "IP blocked successfully")
		}
	case proto.CommandType_UNBLOCK_IP:
		err := a.blocker.UnblockIP(cmd.GetTargetIp())
		if err != nil {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, err.Error())
		} else {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), true, "IP unblocked successfully")
		}
	case proto.CommandType_PATCH_CONFIG:
		if cmd.GetMatchRegex() == "__DASRS_AI_RULE_TEST__" {
			var req struct {
				RuleContent     string `json:"rule_content"`
				CommandTemplate string `json:"command_template"`
			}
			if err := json.Unmarshal([]byte(cmd.GetReplaceContent()), &req); err != nil {
				a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, "invalid ai rule test payload: "+err.Error())
				return
			}

			output, err := a.ruleDeployer.TestRule(req.RuleContent, req.CommandTemplate)
			if err != nil {
				a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, err.Error())
			} else {
				message := "Suricata rule test passed"
				if output != "" {
					message += " | " + output
				}
				a.grpcClient.SendCommandResult(cmd.GetCommandId(), true, message)
			}
			return
		}

		if cmd.GetMatchRegex() == "__DASRS_AI_RULE_DEPLOY__" {
			err := a.ruleDeployer.DeployRule(cmd.GetConfigPath(), cmd.GetReplaceContent())
			if err != nil {
				a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, err.Error())
			} else {
				a.grpcClient.SendCommandResult(cmd.GetCommandId(), true, "Suricata rule deployed successfully")
			}
			return
		}

		err := a.patcher.SafePatch(cmd.GetConfigPath(), cmd.GetMatchRegex(), cmd.GetReplaceContent())
		if err != nil {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), false, err.Error())
		} else {
			a.grpcClient.SendCommandResult(cmd.GetCommandId(), true, "Config patched successfully")
		}
	default:
		log.Printf("Unknown command type: %s", cmd.GetType())
	}
}

func (a *Agent) reportServicesLoop() {
	a.reportServices()

	interval := time.Duration(a.cfg.ServiceScanInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		a.reportServices()
	}
}

func (a *Agent) reportServices() {
	if a.scanner == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	services, err := a.scanner.Scan(ctx)
	if err != nil {
		log.Printf("Failed to scan local services: %v", err)
		return
	}

	if err := a.grpcClient.RegisterAgent(services); err != nil {
		log.Printf("Failed to report local services: %v", err)
		return
	}

	log.Printf("Reported %d local services to master", len(services))
}

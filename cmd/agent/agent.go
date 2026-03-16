package main

import (
	"log"

	"security-response-system/internal/agent/client"
	"security-response-system/internal/agent/collector"
	"security-response-system/internal/agent/executor"
	"security-response-system/internal/proto"
)

// Agent Agent 客户端
type Agent struct {
	cfg        *Config
	grpcClient *client.Client
	collector  *collector.SuricataCollector
	blocker    *executor.IPBlocker
	patcher    *executor.ConfigPatcher
}

func NewAgent(
	cfg *Config,
	grpcClient *client.Client,
	collector *collector.SuricataCollector,
	blocker *executor.IPBlocker,
	patcher *executor.ConfigPatcher,
) *Agent {
	return &Agent{
		cfg:        cfg,
		grpcClient: grpcClient,
		collector:  collector,
		blocker:    blocker,
		patcher:    patcher,
	}
}

func (a *Agent) Start() {
	log.Println("Starting agent...")

	// 启动日志采集
	err := a.collector.Start(a.handleAlert)
	if err != nil {
		log.Printf("Failed to start collector: %v", err)
	}

	// 连接 Master 并启动双向流
	a.grpcClient.Start(a.handleCommand)
}

func (a *Agent) Stop() {
	a.grpcClient.Stop()
	a.collector.Stop()
}

func (a *Agent) handleAlert(alert *proto.AlertReportRequest) {
	// 发送到 Master
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

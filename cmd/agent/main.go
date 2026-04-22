package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "google.golang.org/protobuf/runtime/protoimpl"

	"security-response-system/internal/agent/client"
	"security-response-system/internal/agent/collector"
	"security-response-system/internal/agent/discovery"
	"security-response-system/internal/agent/executor"
)

func main() {
	configPath := flag.String("config", "configs/agent.yaml", "path to config file")
	testMasterConn := flag.Bool("test-master-conn", false, "test connectivity to master and exit")
	verbose := flag.Bool("v", false, "enable verbose logging")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}

	log.Println("Starting DASRS Agent...")

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Configuration loaded:")
	log.Printf("  - Master Address: %s", cfg.MasterAddress)
	log.Printf("  - Master HTTP Address: %s", cfg.MasterHTTPAddress)
	log.Printf("  - Suricata Log Path: %s", cfg.SuricataLogPath)
	log.Printf("  - Suricata Rule Path: %s", cfg.SuricataRulePath)
	log.Printf("  - Suricata Test Command: %s", cfg.SuricataTestCmd)
	log.Printf("  - Agent Name: %s", cfg.AgentName)
	log.Printf("  - Reconnect Interval: %ds", cfg.ReconnectInterval)
	log.Printf("  - Heartbeat Interval: %ds", cfg.HeartbeatInterval)
	log.Printf("  - Service Scan Interval: %ds", cfg.ServiceScanInterval)

	if _, err := os.Stat(cfg.SuricataLogPath); os.IsNotExist(err) {
		log.Printf("Warning: Suricata log path does not exist: %s", cfg.SuricataLogPath)
		log.Println("The agent will continue to run but no alerts will be collected until the log file is available.")
	}

	if *testMasterConn {
		log.Printf("Testing master connectivity to %s...", cfg.MasterAddress)
		success, msg := client.TestMasterConnectivity(cfg.MasterAddress)
		if success {
			log.Printf("Master connectivity test succeeded: %s", msg)
		} else {
			log.Fatalf("Master connectivity test failed: %s", msg)
		}
		return
	}

	log.Println("Initializing executors...")
	blocker := executor.NewIPBlocker()
	patcher := executor.NewConfigPatcher()
	ruleDeployer := executor.NewSuricataRuleDeployer(cfg.SuricataRulePath, cfg.SuricataReloadCmd, cfg.SuricataTestCmd)
	scanner := discovery.NewLocalServiceScanner()

	log.Printf("Connecting to Master at %s...", cfg.MasterAddress)
	grpcClient := client.NewClient(cfg.MasterAddress, cfg.MasterHTTPAddress, cfg.AgentName, cfg.ReconnectInterval)

	localIP := grpcClient.GetLocalIP()
	log.Printf("Agent identified with IP: %s", localIP)

	log.Println("Initializing Suricata collector...")
	logCollector := collector.NewSuricataCollector(cfg.SuricataLogPath, localIP, cfg.MonitorIP)
	trafficContext := collector.NewTrafficContextCollector(localIP, cfg.MonitorIP)
	if err := trafficContext.Start(); err != nil {
		log.Printf("Warning: traffic context collector unavailable: %v", err)
	} else {
		log.Println("Traffic context collector started")
		logCollector.SetTrafficContextProvider(trafficContext)
	}

	agent := NewAgent(cfg, grpcClient, logCollector, scanner, blocker, patcher, ruleDeployer)

	log.Println("Agent starting...")
	go agent.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.Printf("Received signal: %v", sig)

	log.Println("Shutting down agent...")
	agent.Stop()
	log.Println("Agent stopped gracefully")

	fmt.Println("\nAgent Statistics:")
	fmt.Printf("  - Alerts Collected: %d\n", logCollector.GetAlertCount())
	fmt.Printf("  - IPs Blocked: %d\n", blocker.GetBlockCount())
	fmt.Printf("  - Configs Patched: %d\n", patcher.GetPatchCount())
}

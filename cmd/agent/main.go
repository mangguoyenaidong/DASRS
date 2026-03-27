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
	"security-response-system/internal/agent/executor"
)

func main() {
	// 命令行参数
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	testMasterConn := flag.Bool("test-master-conn", false, "测试与 Master 的连通性并退出")
	verbose := flag.Bool("v", false, "enable verbose logging")
	flag.Parse()

	// 设置日志级别
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}

	log.Println("Starting DASRS Agent...")

	// 加载配置
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Configuration loaded:")
	log.Printf("  - Master Address: %s", cfg.MasterAddress)
	log.Printf("  - Suricata Log Path: %s", cfg.SuricataLogPath)
	log.Printf("  - Reconnect Interval: %ds", cfg.ReconnectInterval)
	log.Printf("  - Heartbeat Interval: %ds", cfg.HeartbeatInterval)

	// 检查配置文件是否存在
	if _, err := os.Stat(cfg.SuricataLogPath); os.IsNotExist(err) {
		log.Printf("Warning: Suricata log path does not exist: %s", cfg.SuricataLogPath)
		log.Println("The agent will continue to run but no alerts will be collected until the log file is available.")
	}

	// 如果是连接测试模式，则执行测试并退出
	if *testMasterConn {
		log.Printf("正在测试与 Master (%s) 的连通性...", cfg.MasterAddress)
		success, msg := client.TestMasterConnectivity(cfg.MasterAddress)
		if success {
			log.Printf("Master 连通性测试成功: %s", msg)
		} else {
			log.Fatalf("Master 连通性测试失败: %s", msg)
		}
		return // 测试完成后退出
	}

	// 初始化执行器
	log.Println("Initializing executors...")
	blocker := executor.NewIPBlocker()
	patcher := executor.NewConfigPatcher()

	// 初始化采集器
	log.Println("Initializing Suricata collector...")
	logCollector := collector.NewSuricataCollector(cfg.SuricataLogPath)

	// 初始化 gRPC 客户端
	log.Printf("Connecting to Master at %s...", cfg.MasterAddress)
	grpcClient := client.NewClient(cfg.MasterAddress, cfg.ReconnectInterval)

	// 创建 Agent
	agent := NewAgent(cfg, grpcClient, logCollector, blocker, patcher)

	// 启动
	log.Println("Agent starting...")
	go agent.Start()

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.Printf("Received signal: %v", sig)

	log.Println("Shutting down agent...")
	agent.Stop()
	log.Println("Agent stopped gracefully")

	// 输出统计信息
	fmt.Println("\nAgent Statistics:")
	fmt.Printf("  - Alerts Collected: %d\n", logCollector.GetAlertCount())
	fmt.Printf("  - IPs Blocked: %d\n", blocker.GetBlockCount())
	fmt.Printf("  - Configs Patched: %d\n", patcher.GetPatchCount())
}

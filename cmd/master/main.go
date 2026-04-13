package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "google.golang.org/protobuf/runtime/protoimpl"

	"security-response-system/internal/master/core"
	"security-response-system/internal/master/grpc"
	"security-response-system/internal/master/api"
	"security-response-system/internal/master/model"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	// 加载配置
	cfg, err := model.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化数据库
	db, err := model.InitDB(cfg)
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	// 自动迁移数据库表结构
	if err := model.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migration completed")

	// 初始化 Redis
	redisClient, err := model.InitRedis(cfg)
	if err != nil {
		log.Fatalf("Failed to init redis: %v", err)
	}

	// 启动情报引擎
	engine := core.NewIntelligenceEngine(db, redisClient, cfg)

	// 启动 gRPC 服务器
	grpcServer := grpc.NewServer(cfg, engine, db, redisClient)
	go func() {
		if err := grpcServer.Start(); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	// 启动 HTTP API 服务器
	apiServer := api.NewServer(cfg, db, redisClient, engine, grpcServer)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("HTTP API server failed: %v", err)
		}
	}()

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")
	grpcServer.Stop()
	apiServer.Close()
}

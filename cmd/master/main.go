package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "google.golang.org/protobuf/runtime/protoimpl"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/api"
	"security-response-system/internal/master/core"
	"security-response-system/internal/master/grpc"
	"security-response-system/internal/master/model"
	"security-response-system/internal/master/service"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := model.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := model.InitDB(cfg)
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	if err := model.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migration completed")

	redisClient, err := model.InitRedis(cfg)
	if err != nil {
		log.Fatalf("Failed to init redis: %v", err)
	}

	engine := core.NewIntelligenceEngine(db, redisClient, cfg)

	var aiProvider ai.Provider
	if cfg.Master.AI.Enabled {
		aiProvider, err = ai.NewProviderFromConfig(cfg)
		if err != nil {
			log.Fatalf("Failed to init AI provider: %v", err)
		}
	}

	aiRuleService := service.NewAIRuleService(db, aiProvider, cfg)
	aiAlertService := service.NewAIAlertService(db, aiProvider)

	grpcServer := grpc.NewServer(cfg, engine, db, redisClient)
	go func() {
		if err := grpcServer.Start(); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	apiServer := api.NewServerWithAI(cfg, db, redisClient, engine, grpcServer, aiRuleService, aiAlertService)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("HTTP API server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")
	grpcServer.Stop()
	apiServer.Close()
}

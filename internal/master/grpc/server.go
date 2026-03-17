package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"security-response-system/internal/common"
	"security-response-system/internal/master/core"
	"security-response-system/internal/master/model"
	"security-response-system/internal/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"gorm.io/gorm"
)

// AgentInfo Agent 连接信息
type AgentInfo struct {
	AgentID     string
	Hostname    string
	IP          string
	ConnectedAt time.Time
	LastSeen    time.Time
}

// Server gRPC 服务器
type Server struct {
	proto.UnimplementedSecurityServiceServer
	grpcServer   *grpc.Server
	cfg          *model.Config
	engine       *core.IntelligenceEngine
	db           interface{}
	redis        interface{}
	logger       *common.Logger
	streams      sync.Map
	agentStreams sync.Map             // 存储 Agent 流
	agentClients sync.Map             // 存储 Agent 客户端信息
	commandQueue chan *CommandRequest // 命令队列
	stopChan     chan struct{}
}

// CommandRequest 命令请求
type CommandRequest struct {
	AgentID   string
	Command   *proto.CommandMessage
	CreatedAt time.Time
}

// NewServer 创建服务器
func NewServer(cfg *model.Config, engine *core.IntelligenceEngine, db interface{}, redis interface{}) *Server {
	return &Server{
		cfg:          cfg,
		engine:       engine,
		db:           db,
		redis:        redis,
		logger:       common.NewLogger("[gRPC-Server]"),
		agentStreams: sync.Map{},
		agentClients: sync.Map{},
		commandQueue: make(chan *CommandRequest, 100),
		stopChan:     make(chan struct{}),
	}
}

// Start 启动服务器
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Master.Host, s.cfg.Master.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcServer = grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
	)

	// 注册服务
	proto.RegisterSecurityServiceServer(s.grpcServer, s)

	// 启动命令分发协程
	go s.dispatchCommands()

	log.Printf("gRPC server listening on %s", addr)

	return s.grpcServer.Serve(lis)
}

// Stop 停止服务器
func (s *Server) Stop() {
	close(s.stopChan)
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// dispatchCommands 处理命令队列，将命令推送到对应的 Agent 流
func (s *Server) dispatchCommands() {
	for {
		select {
		case <-s.stopChan:
			return
		case cmdReq := <-s.commandQueue:
			if err := s.PushCommand(cmdReq.AgentID, cmdReq.Command); err != nil {
				s.logger.Error("Failed to dispatch command to %s: %v", cmdReq.AgentID, err)
			} else {
				s.logger.Info("Command sent to %s: %s", cmdReq.AgentID, cmdReq.Command.GetType().String())
			}
		}
	}
}

// CommandStream 双向流处理 - 接收结果，由于发送由 PushCommand 处理，我们只需要循环接收
func (s *Server) CommandStream(stream proto.SecurityService_CommandStreamServer) error {
	ctx := stream.Context()
	var agentID string

	// 获取对端 IP
	peerIP := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		if addr := p.Addr; addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				peerIP = tcpAddr.IP.String()
			} else {
				peerIP = addr.String()
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			if agentID != "" {
				s.cleanupAgent(agentID)
			}
			return ctx.Err()
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if agentID != "" {
				s.cleanupAgent(agentID)
			}
			return err
		}

		if agentID == "" {
			agentID = msg.GetAgentId()
			if agentID == "" {
				s.logger.Error("Received message with empty AgentID, dropping connection")
				return fmt.Errorf("missing agent id")
			}
			// 保存流
			s.agentStreams.Store(agentID, stream)
			s.logger.Info("Agent stream connected: %s", agentID)
		}

		// 解析消息（如果 command_id == "register"，这是一个注册消息，附加信息在 message 里）
		if msg.GetCommandId() == "register" {
			hostname := msg.GetMessage()
			if hostname == "" {
				hostname = "unknown"
			}
			s.agentClients.Store(agentID, &AgentInfo{
				AgentID:     agentID,
				Hostname:    hostname,
				IP:          peerIP,
				ConnectedAt: time.Now(),
				LastSeen:    time.Now(),
			})
			s.RegisterAgentInDB(agentID, hostname, peerIP, "")
			s.logger.Info("Agent %s registered with hostname %s IP %s", agentID, hostname, peerIP)
			continue
		}

		// 处理正常的命令执行结果
		s.handleCommandResult(agentID, msg)
	}
}

// cleanupAgent 清理下线的 Agent 资源
func (s *Server) cleanupAgent(agentID string) {
	s.agentStreams.Delete(agentID)
	s.agentClients.Delete(agentID)
	s.SetAgentOffline(agentID)
	s.logger.Info("Agent disconnected: %s", agentID)
}

// handleCommandResult 处理命令执行结果
func (s *Server) handleCommandResult(agentID string, result *proto.CommandResult) {
	s.logger.Info("Command result from %s: CommandID=%s, Success=%v, Message=%s",
		agentID, result.GetCommandId(), result.GetSuccess(), result.GetMessage())

	// 保存到数据库
	db := s.db.(*gorm.DB)
	opLog := &model.OperationLog{
		CommandID:       result.GetCommandId(),
		CommandType:     "result_report",
		Target:          agentID,
		Result:          boolToInt(result.GetSuccess()),
		Message:         result.GetMessage(),
		ExecutionTimeMs: time.Now().UnixMilli(),
		CreatedAt:       time.Now(),
	}
	db.Create(opLog)

	// 更新 Agent 最后活动时间
	if _, ok := s.agentClients.Load(agentID); ok {
		db.Model(&model.AgentNode{}).Where("agent_id = ?", agentID).
			Update("last_seen_at", time.Now())
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SendHeartbeat 处理心跳
func (s *Server) SendHeartbeat(ctx context.Context, req *proto.HeartbeatRequest) (*proto.HeartbeatResponse, error) {
	s.logger.Debug("Heartbeat from %s (%s)", req.GetHostname(), req.GetIp())

	// 从上线 Agent 中找，如果是已有的 Agent，更新最后活动时间
	var agentID string
	s.agentClients.Range(func(key, value interface{}) bool {
		info := value.(*AgentInfo)
		// HeartbeatRequest 没有 AgentID，只能通过 hostname 或 ip 匹配，这里假定 hostname 可以对应上
		if info.Hostname == req.GetHostname() {
			agentID = info.AgentID
			return false // stop iteration
		}
		return true
	})

	if agentID != "" {
		if info, ok := s.agentClients.Load(agentID); ok {
			info.(*AgentInfo).LastSeen = time.Now()
		}
		s.UpdateAgentLastSeen(agentID)
	}

	return &proto.HeartbeatResponse{Success: true, Message: "OK"}, nil
}

// ReportAlert 处理告警上报
func (s *Server) ReportAlert(ctx context.Context, req *proto.AlertReportRequest) (*proto.AlertReportResponse, error) {
	s.logger.Info("ReportAlert received: SID=%s, SourceIP=%s, Severity=%s", req.GetSid(), req.GetSourceIp(), req.GetSeverity())

	alert := &core.Alert{
		SID:           req.GetSid(),
		Payload:       req.GetPayload(),
		SourceIP:      req.GetSourceIp(),
		AssetInfo:     req.GetAssetInfo(),
		Timestamp:     req.GetTimestamp(),
		Severity:      req.GetSeverity(),
		SignatureName: req.GetSignatureName(),
	}

	decision, err := s.engine.Analyze(ctx, alert)
	if err != nil {
		s.logger.Error("Analysis failed: %v", err)
		return &proto.AlertReportResponse{
			Success: false,
			Message: fmt.Sprintf("Analysis failed: %v", err),
		}, err
	}

	// 保存告警到数据库
	alertLog := &model.AlertLog{
		AlertID:       decision.AlertID,
		SourceIP:      alert.SourceIP,
		SID:           alert.SID,
		SignatureName: alert.SignatureName,
		Severity:      alert.Severity,
		Payload:       alert.Payload,
		AssetInfo:     alert.AssetInfo,
		RiskScore:     decision.Score,
		Action:        decision.Action,
		Status:        0,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	db := s.db.(*gorm.DB)
	result := db.Create(alertLog)
	if result.Error != nil {
		s.logger.Error("Failed to save alert: %v", result.Error)
	} else {
		s.logger.Info("Alert saved successfully: ID=%d, AlertID=%s", alertLog.ID, alertLog.AlertID)
	}

	// 如果分析结果是需要阻断，直接加入阻断命令队列
	if decision.Action == "block" && alert.SourceIP != "" {
		s.logger.Info("Auto blocking IP %s for alert %s", alert.SourceIP, decision.AlertID)

		cmd := &proto.CommandMessage{
			CommandId: fmt.Sprintf("cmd-block-%d", time.Now().Unix()),
			Type:      proto.CommandType_BLOCK_IP,
			TargetIp:  alert.SourceIP,
		}

		// 寻找所有已连接的 Agent 下发阻断命令
		agents := s.GetConnectedAgents()
		for _, agent := range agents {
			s.QueueCommand(agent.AgentID, cmd)
		}
	}

	return &proto.AlertReportResponse{
		Success: true,
		Message: decision.Reason,
		AlertId: decision.AlertID,
	}, nil
}

// PushCommand 向指定 Agent 推送指令
func (s *Server) PushCommand(agentID string, cmd *proto.CommandMessage) error {
	streamInterface, ok := s.agentStreams.Load(agentID)
	if !ok {
		return fmt.Errorf("agent %s not connected", agentID)
	}

	stream := streamInterface.(proto.SecurityService_CommandStreamServer)

	return stream.Send(cmd)
}

// QueueCommand 将命令加入队列，推送给指定 Agent
func (s *Server) QueueCommand(agentID string, cmd *proto.CommandMessage) {
	s.commandQueue <- &CommandRequest{
		AgentID:   agentID,
		Command:   cmd,
		CreatedAt: time.Now(),
	}
}

// GetConnectedAgents 获取所有连接的 Agent
func (s *Server) GetConnectedAgents() []*AgentInfo {
	var agents []*AgentInfo
	s.agentClients.Range(func(key, value interface{}) bool {
		if info, ok := value.(*AgentInfo); ok {
			agents = append(agents, info)
		}
		return true
	})
	return agents
}

// IsAgentConnected 检查 Agent 是否在线
func (s *Server) IsAgentConnected(agentID string) bool {
	_, ok := s.agentStreams.Load(agentID)
	return ok
}

// GetGRPCServer 获取 gRPC 服务器实例
func (s *Server) GetGRPCServer() *grpc.Server {
	return s.grpcServer
}

// RegisterAgentInDB 在数据库中注册 Agent
func (s *Server) RegisterAgentInDB(agentID, hostname, ip, name string) error {
	db := s.db.(*gorm.DB)
	now := time.Now()

	var agent model.AgentNode
	result := db.Where("agent_id = ?", agentID).First(&agent)
	if result.Error != nil {
		// 新 Agent，注册
		agent = model.AgentNode{
			AgentID:      agentID,
			Name:         name,
			Hostname:     hostname,
			IP:           ip,
			Status:       1,
			LastSeenAt:   now,
			RegisteredAt: now,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		return db.Create(&agent).Error
	}

	// 更新现有 Agent
	agent.LastSeenAt = now
	agent.Status = 1
	agent.Hostname = hostname
	agent.IP = ip
	if name != "" {
		agent.Name = name
	}
	agent.UpdatedAt = now
	return db.Save(&agent).Error
}

// UpdateAgentLastSeen 更新 Agent 最后活动时间
func (s *Server) UpdateAgentLastSeen(agentID string) error {
	db := s.db.(*gorm.DB)
	return db.Model(&model.AgentNode{}).
		Where("agent_id = ?", agentID).
		Update("last_seen_at", time.Now()).Error
}

// SetAgentOffline 设置 Agent 离线状态
func (s *Server) SetAgentOffline(agentID string) error {
	db := s.db.(*gorm.DB)
	return db.Model(&model.AgentNode{}).
		Where("agent_id = ?", agentID).
		Updates(map[string]interface{}{
			"status":     0,
			"updated_at": time.Now(),
		}).Error
}

// GetAllAgentsFromDB 从数据库获取所有 Agent
func (s *Server) GetAllAgentsFromDB() ([]model.AgentNode, error) {
	var agents []model.AgentNode
	db := s.db.(*gorm.DB)
	err := db.Order("created_at DESC").Find(&agents).Error
	return agents, err
}

// GetAgentByID 从数据库获取单个 Agent
func (s *Server) GetAgentByID(agentID string) (*model.AgentNode, error) {
	var agent model.AgentNode
	db := s.db.(*gorm.DB)
	err := db.Where("agent_id = ?", agentID).First(&agent).Error
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

// DeleteAgentFromDB 从数据库删除 Agent
func (s *Server) DeleteAgentFromDB(agentID string) error {
	db := s.db.(*gorm.DB)
	return db.Where("agent_id = ?", agentID).Delete(&model.AgentNode{}).Error
}

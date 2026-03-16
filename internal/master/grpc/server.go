package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/gorm"
	"security-response-system/internal/common"
	"security-response-system/internal/master/core"
	"security-response-system/internal/master/model"
	"security-response-system/internal/proto"
)

// AgentInfo Agent 连接信息
type AgentInfo struct {
	AgentID    string
	Hostname   string
	IP         string
	ConnectedAt time.Time
	LastSeen   time.Time
}

// Server gRPC 服务器
type Server struct {
	proto.UnimplementedCommandStreamServiceServer
	grpcServer   *grpc.Server
	cfg          *model.Config
	engine       *core.IntelligenceEngine
	db           interface{}
	redis        interface{}
	logger       *common.Logger
	streams      sync.Map
	agentStreams sync.Map // 存储 Agent 流
	agentClients sync.Map // 存储 Agent 客户端信息
	commandQueue chan *CommandRequest // 命令队列
}

// CommandRequest 命令请求
type CommandRequest struct {
	AgentID   string
	Command   *proto.Command
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
	proto.RegisterCommandStreamServiceServer(s.grpcServer, s)

	log.Printf("gRPC server listening on %s", addr)

	return s.grpcServer.Serve(lis)
}

// Stop 停止服务器
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// CommandStream 双向流处理 - 完整实现
func (s *Server) CommandStream(stream proto.CommandStreamService_CommandStreamServer) error {
	ctx := stream.Context()
	var agentID string
	var agentHostname string
	var agentIP string
	var agentName string

	for {
		select {
		case <-ctx.Done():
			// Agent 断开连接，清理资源
			if agentID != "" {
				s.agentStreams.Delete(agentID)
				s.agentClients.Delete(agentID)
				s.SetAgentOffline(agentID)
				s.logger.Info("Agent disconnected: %s", agentID)
			}
			return ctx.Err()
		default:
		}

		// 接收来自 Agent 的消息
		msg, err := stream.Recv()
		if err != nil {
			// Agent 断开连接
			if agentID != "" {
				s.agentStreams.Delete(agentID)
				s.agentClients.Delete(agentID)
				s.SetAgentOffline(agentID)
				s.logger.Info("Agent disconnected: %s", agentID)
			}
			return err
		}

		// 根据消息类型处理
		if msg.GetIsHeartbeat() {
			// 处理心跳
			hostname := msg.GetCommandId() // 使用 command_id 字段传递 hostname
			if agentID == "" {
				// 首次连接，生成 Agent ID
				agentID = fmt.Sprintf("agent-%s", uuid.New().String()[:8])
				agentHostname = hostname
				s.agentClients.Store(agentID, &AgentInfo{
					AgentID:     agentID,
					Hostname:    hostname,
					IP:          agentIP,
					ConnectedAt: time.Now(),
					LastSeen:    time.Now(),
				})
				s.agentStreams.Store(agentID, stream)

				// 在数据库中注册 Agent
				s.RegisterAgentInDB(agentID, hostname, agentIP, agentName)
				s.logger.Info("Agent connected: %s (%s)", agentID, hostname)
			} else {
				// 更新心跳时间
				if info, ok := s.agentClients.Load(agentID); ok {
					info.(*AgentInfo).LastSeen = time.Now()
				}
				// 更新数据库
				s.UpdateAgentLastSeen(agentID)
			}
			s.logger.Debug("Heartbeat from %s", agentHostname)

		} else if msg.GetIsAlertReport() {
			// 处理告警上报
			s.logger.Info("Stream alert received via Command: SID=%s, SourceIP=%s",
				msg.GetCommandId(), msg.GetTargetIp())

		} else if msg.GetIsCommandResult() {
			// 处理命令执行结果 - 从 CommandId 获取 command_id
			result := &proto.CommandResult{
				CommandId:     msg.GetCommandId(),
				Success:       msg.GetType() == proto.Command_BLOCK_IP || msg.GetType() == proto.Command_UNBLOCK_IP,
				Message:       msg.GetMatchRegex(),
				ExecutionTime: msg.GetTimestamp(),
			}
			s.handleCommandResult(agentID, result)

		} else if msg.GetType() != proto.Command_COMMAND_TYPE_UNSPECIFIED {
			// 处理收到的指令（从其他 Agent 发回的）
			s.logger.Info("Command received from %s: %v", agentID, msg.GetType())
		}

		// 检查是否有待发送给该 Agent 的命令
		if agentID != "" {
			select {
			case cmdReq := <-s.commandQueue:
				if cmdReq.AgentID == agentID {
					if err := stream.Send(cmdReq.Command); err != nil {
						s.logger.Error("Failed to send command to %s: %v", agentID, err)
					} else {
						s.logger.Info("Command sent to %s: %s", agentID, cmdReq.Command.GetType().String())
					}
				} else {
					// 不是发给这个 Agent 的命令，放回队列
					s.commandQueue <- cmdReq
				}
			default:
				// 没有待发送的命令，发送心跳保持连接
				hbCmd := &proto.Command{
					CommandId:   agentHostname,
					Timestamp:   time.Now().UnixMilli(),
					IsHeartbeat: true,
				}
				stream.Send(hbCmd)
			}
		}
	}
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
		ExecutionTimeMs: result.GetExecutionTime(),
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
	s.logger.Info("Heartbeat from %s (%s)", req.GetHostname(), req.GetIp())
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

	return &proto.AlertReportResponse{
		Success: true,
		Message: decision.Reason,
		AlertId: decision.AlertID,
	}, nil
}

// PushCommand 向指定 Agent 推送指令
func (s *Server) PushCommand(agentID string, cmd *proto.Command) error {
	stream, ok := s.agentStreams.Load(agentID)
	if !ok {
		return fmt.Errorf("agent %s not connected", agentID)
	}
	return stream.(proto.CommandStreamService_CommandStreamServer).Send(cmd)
}

// QueueCommand 将命令加入队列，推送给指定 Agent
func (s *Server) QueueCommand(agentID string, cmd *proto.Command) {
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
			"status":      0,
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

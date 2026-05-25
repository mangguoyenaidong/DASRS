package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"security-response-system/internal/agent/discovery"
	"security-response-system/internal/proto"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	address           string
	reconnectInterval int
	conn              *grpc.ClientConn
	stream            proto.SecurityService_CommandStreamClient
	stopChan          chan struct{}
	hostname          string
	agentID           string
	localIP           string
	osType            string
	httpAddress       string
	agentName         string
	httpClient        *http.Client
	serviceClient     proto.SecurityServiceClient
}

func NewClient(address, httpAddress, agentName string, reconnectInterval int) *Client {
	localIP := detectLocalIP()
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "agent-host"
	}

	return &Client{
		address:           address,
		reconnectInterval: reconnectInterval,
		stopChan:          make(chan struct{}),
		hostname:          hostname,
		agentID:           fmt.Sprintf("agent-%s", uuid.New().String()[:8]),
		localIP:           localIP,
		osType:            runtime.GOOS,
		httpAddress:       httpAddress,
		agentName:         agentName,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Start(handler func(*proto.CommandMessage)) {
	go c.connect(handler)
}

func (c *Client) connect(handler func(*proto.CommandMessage)) {
ReconnectLoop:
	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		var err error
		c.conn, err = grpc.NewClient(c.address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			log.Printf("Failed to connect to master: %v, retrying...", err)
			time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
			continue ReconnectLoop
		}

		log.Printf("Connecting to master at %s, starting bidirectional stream...", c.address)

		c.serviceClient = proto.NewSecurityServiceClient(c.conn)

		ctx, cancel := context.WithCancel(context.Background())
		c.stream, err = c.serviceClient.CommandStream(ctx)
		if err != nil {
			log.Printf("Failed to create stream: %v", err)
			cancel()
			c.conn.Close()
			time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
			continue ReconnectLoop
		}

		// Send registration message
		regMsg := &proto.CommandResult{
			AgentId:   c.agentID,
			CommandId: "register",
			Success:   true,
			Message:   c.hostname,
		}
		if err := c.stream.Send(regMsg); err != nil {
			log.Printf("Failed to send registration message: %v", err)
			cancel()
			c.conn.Close()
			time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
			continue ReconnectLoop
		}
		log.Printf("Connected to master at %s; command stream registered as %s", c.address, c.agentID)

		go c.sendHeartbeats(ctx)

		for {
			select {
			case <-c.stopChan:
				cancel()
				c.conn.Close()
				return
			case <-ctx.Done():
				cancel()
				c.conn.Close()
				continue ReconnectLoop
			default:
			}

			cmd, err := c.stream.Recv()
			if err != nil {
				log.Printf("Stream error: %v", err)
				cancel()
				c.conn.Close()
				time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
				continue ReconnectLoop
			}
			handler(cmd)
		}
	}
}

func (c *Client) sendHeartbeats(ctx context.Context) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sendUnaryHeartbeat()
		}
	}
}

func (c *Client) sendUnaryHeartbeat() {
	if c.serviceClient == nil {
		return
	}

	req := &proto.HeartbeatRequest{
		Hostname: c.hostname,
		Ip:       c.localIP,
		CpuLoad:  0.0,
		MemLoad:  0.0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.serviceClient.SendHeartbeat(ctx, req)
	if err != nil {
		log.Printf("Failed to send heartbeat: %v", err)
	}
}

func (c *Client) ReportAlert(alert *proto.AlertReportRequest) (*proto.AlertReportResponse, error) {
	if c.serviceClient == nil {
		return nil, fmt.Errorf("not connected to master")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.serviceClient.ReportAlert(ctx, alert)
}

func (c *Client) SendCommandResult(commandID string, success bool, message string) {
	if c.stream == nil {
		log.Printf("Stream not available, cannot send command result")
		return
	}

	res := &proto.CommandResult{
		AgentId:   c.agentID,
		CommandId: commandID,
		Success:   success,
		Message:   message,
	}

	if err := c.stream.Send(res); err != nil {
		log.Printf("Failed to send command result: %v", err)
	} else {
		log.Printf("Command result sent: CommandID=%s, Success=%v", commandID, success)
	}
}

func (c *Client) Stop() {
	close(c.stopChan)
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) GetAgentID() string {
	return c.agentID
}

func (c *Client) GetLocalIP() string {
	return c.localIP
}

func (c *Client) RegisterAgent(services []discovery.ServiceRecord) error {
	if c.httpAddress == "" {
		return fmt.Errorf("master http address is empty")
	}

	payload := map[string]interface{}{
		"agent_id":          c.agentID,
		"hostname":          c.hostname,
		"ip":                c.localIP,
		"name":              c.agentName,
		"os_type":           c.osType,
		"service_inventory": services,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal registration payload: %w", err)
	}

	url := fmt.Sprintf("http://%s/api/agents/register", c.httpAddress)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("register agent via http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register agent failed: status=%s body=%s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	return nil
}

func detectLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
			continue
		}

		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}

		return ip.String()
	}

	return "127.0.0.1"
}

// TestMasterConnectivity 尝试连接到 Master 并发送一个心跳请求以测试连通性。
// 它返回一个布尔值表示测试是否成功，以及一个描述性的消息。
func TestMasterConnectivity(masterAddr string) (bool, string) {
	// 建立一个临时的 gRPC 连接用于测试
	conn, err := grpc.NewClient(masterAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false, fmt.Sprintf("无法连接到 Master (%s): %v", masterAddr, err)
	}
	defer conn.Close()

	c := proto.NewSecurityServiceClient(conn)
	// 设置一个短的上下文超时，以避免长时间等待连接或响应
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 发送一个模拟的心跳请求
	resp, err := c.SendHeartbeat(ctx, &proto.HeartbeatRequest{
		Hostname: "test-agent", // 用于测试的虚拟主机名
		Ip:       "127.0.0.1",  // 用于测试的虚拟 IP
		CpuLoad:  0.0,
		MemLoad:  0.0,
	})
	if err != nil {
		return false, fmt.Sprintf("发送心跳请求失败: %v", err)
	}

	if resp.Success {
		return true, fmt.Sprintf("Master 连通性测试成功: %s", resp.Message)
	}
	return false, fmt.Sprintf("Master 响应失败: %s", resp.Message)
}

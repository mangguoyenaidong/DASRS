package client

import (
	"context"
	"fmt"
	"log"
	"time"

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
	serviceClient     proto.SecurityServiceClient
}

func NewClient(address string, reconnectInterval int) *Client {
	return &Client{
		address:           address,
		reconnectInterval: reconnectInterval,
		stopChan:          make(chan struct{}),
		hostname:          "agent-host", // placeholder
		agentID:           fmt.Sprintf("agent-%s", uuid.New().String()[:8]),
	}
}

func (c *Client) Start(handler func(*proto.CommandMessage)) {
	go c.connect(handler)
}

func (c *Client) connect(handler func(*proto.CommandMessage)) {
	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		var err error
		c.conn, err = grpc.Dial(c.address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			log.Printf("Failed to connect to master: %v, retrying...", err)
			time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
			continue
		}

		log.Println("Connected to master, starting bidirectional stream...")

		c.serviceClient = proto.NewSecurityServiceClient(c.conn)

		ctx, cancel := context.WithCancel(context.Background())
		c.stream, err = c.serviceClient.CommandStream(ctx)
		if err != nil {
			log.Printf("Failed to create stream: %v", err)
			cancel()
			time.Sleep(time.Duration(c.reconnectInterval) * time.Second)
			continue
		}

		go c.sendHeartbeats(ctx)

		for {
			select {
			case <-c.stopChan:
				cancel()
				return
			case <-ctx.Done():
				cancel()
				break
			default:
			}

			cmd, err := c.stream.Recv()
			if err != nil {
				log.Printf("Stream error: %v", err)
				cancel()
				break
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
		Ip:       "127.0.0.1",
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

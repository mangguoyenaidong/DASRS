package common

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger 日志工具
type Logger struct {
	*log.Logger
}

func NewLogger(prefix string) *Logger {
	return &Logger{
		log.New(os.Stdout, prefix, log.LstdFlags|log.Lmicroseconds),
	}
}

// Info 信息日志
func (l *Logger) Info(format string, args ...interface{}) {
	l.Printf("[INFO] "+format, args...)
}

// Error 错误日志
func (l *Logger) Error(format string, args ...interface{}) {
	l.Printf("[ERROR] "+format, args...)
}

// Debug 调试日志
func (l *Logger) Debug(format string, args ...interface{}) {
	l.Printf("[DEBUG] "+format, args...)
}

// Warn 警告日志
func (l *Logger) Warn(format string, args ...interface{}) {
	l.Printf("[WARN] "+format, args...)
}

// GinLogger 返回 Gin 中间件
func (l *Logger) GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()

		l.Printf("[HTTP] %3d | %13v | %15s | %-7s %s",
			status,
			latency,
			clientIP,
			method,
			path+"?"+query,
		)
	}
}

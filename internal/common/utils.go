package common

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// GenerateUUID 生成 UUID
func GenerateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetCurrentTimestamp 获取当前时间戳（毫秒）
func GetCurrentTimestamp() int64 {
	return time.Now().UnixMilli()
}

// GetCurrentTime 获取当前时间
func GetCurrentTime() time.Time {
	return time.Now()
}

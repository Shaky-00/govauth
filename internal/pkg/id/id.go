package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// New 生成一个带前缀的简易唯一 ID
func New(prefix string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(buf))
}

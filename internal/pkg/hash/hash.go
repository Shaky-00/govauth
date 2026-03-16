package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// AnySHA256Hex 对任意可 JSON 序列化对象计算 SHA-256 摘要。
func AnySHA256Hex(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// StringSHA256Hex 对字符串计算 SHA-256 摘要。
func StringSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

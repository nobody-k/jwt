package jwt

import (
	"encoding/base64"
	"strings"
)

// EncodeSegment encodes a byte array according to URLEncoding
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// DecodeSegment takes a jwt base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

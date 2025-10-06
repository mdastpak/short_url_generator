package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashURL generates a SHA256 hash of the URL for use as an index key
func HashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

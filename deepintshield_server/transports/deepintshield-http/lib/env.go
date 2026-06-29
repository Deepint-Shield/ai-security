package lib

import "os"

// GetenvCompat prefers the renamed DeepIntShield env var but still honors the
// legacy DeepintShield env var during the migration window.
func GetenvCompat(primary string, legacy string) string {
	if value := os.Getenv(primary); value != "" {
		return value
	}
	return os.Getenv(legacy)
}

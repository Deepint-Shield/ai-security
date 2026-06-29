package handlers

import "github.com/deepint-shield/ai-security/core/schemas"

var version string
var logger schemas.Logger

// SetLogger sets the logger for the application.
func SetLogger(l schemas.Logger) {
	logger = l
}

// SetVersion sets the version for the application.
func SetVersion(v string) {
	version = v
}

func GetVersion() string {
	return version
}

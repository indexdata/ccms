package global

import (
	"path/filepath"
	"strings"
)

// Version is defined at build time via -ldflags.
var Version = ""

const DefaultPort = "8504"

const ServerProgram = "ccd"

const ClientProgram = "ccc"

func ServerConfigFileName(datadir string) string {
	return filepath.Join(datadir, "ccd.conf")
}

func EncodeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\'' {
			b.WriteRune('\'')
		}
		b.WriteRune(r)
	}
	return b.String()
}

package main

import (
	"os"

	"github.com/realCreeper938/launcher-patcher/internal/patcher"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		runUI()
		return
	}

	lines := make([]string, 0, len(args))
	failed := false
	for _, path := range args {
		result, err := patcher.PatchFile(path)
		lines = append(lines, formatLogLine(path, result, err))
		if err != nil {
			failed = true
		}
	}
	writeRunLog(lines)

	if failed {
		os.Exit(1)
	}
}

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realCreeper938/launcher-patcher/internal/patcher"
)

func lastLogPath() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "launcher-patcher", "last.log")
}

func formatLogLine(path string, result patcher.Result, err error) string {
	if err != nil {
		if path == "" {
			path = result.Input
		}
		if path == "" {
			path = "(未知文件)"
		}
		return fmt.Sprintf("[失败] %s\n       %v", path, err)
	}
	if result.Changed {
		return fmt.Sprintf("[完成] %s\n       输出: %s\n       %s", result.Input, result.Output, result.Note)
	}
	return fmt.Sprintf("[跳过] %s\n       %s", result.Input, result.Note)
}

func writeRunLog(lines []string) {
	header := fmt.Sprintf("launcher-patcher %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	content := header + strings.Join(lines, "\n\n") + "\n"
	path := lastLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(content), 0o644)
}

func logError(err error) {
	if err == nil {
		return
	}
	writeRunLog([]string{"[失败] " + err.Error()})
}

var errUINotAvailable = errors.New("图形界面仅支持 Windows")

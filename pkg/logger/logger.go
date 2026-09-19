package logger

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	enabled    atomic.Bool
	showDetail atomic.Bool
)

func init() {
	enabled.Store(true)
	showDetail.Store(true)
}

// 全局日志开关
func SetEnabled(enable bool) {
	enabled.Store(enable)
}

// 查询日志是否开启
func IsEnabled() bool {
	return enabled.Load()
}

// 设置是否显示详细信息（时间戳、调用位置）
func SetShowDetail(show bool) {
	showDetail.Store(show)
}

// 打印 DEBUG 级别日志
func Debug(format string, args ...any) {
	print("DEBUG", format, args...)
}

// 打印 INFO 级别日志
func Info(format string, args ...any) {
	print("INFO", format, args...)
}

// 打印 WARN 级别日志
func Warn(format string, args ...any) {
	print("WARN", format, args...)
}

// 打印 ERROR 级别日志
func Error(format string, args ...any) {
	print("ERROR", format, args...)
}

// 核心打印控制，格式化消息并按开关输出
func print(level, format string, args ...any) {
	if !enabled.Load() {
		return
	}

	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}

	if showDetail.Load() {
		now := time.Now().Format("2006-01-02 15:04:05.000")
		caller := getCallerInfo()
		fmt.Printf("[%s] [%-5s] [%s] %s\n", now, level, caller, msg)
	} else {
		fmt.Printf("[%s] %s\n", level, msg)
	}
}

// 自动获取调用者信息（文件名:行号）
func getCallerInfo() string {
	// 0: getCallerInfo, 1: print, 2: Info/Debug/..., 3: caller
	_, file, line, ok := runtime.Caller(3)
	if ok {
		return fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	return "Unknown"
}

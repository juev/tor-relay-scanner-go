package scanner

import (
	"fmt"
	"io"
	"log"
	"os"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	// LogLevelDebug is for debug messages
	LogLevelDebug LogLevel = iota
	// LogLevelInfo is for informational messages
	LogLevelInfo
	// LogLevelWarn is for warning messages
	LogLevelWarn
	// LogLevelError is for error messages
	LogLevelError
)

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	logger *log.Logger
	silent bool
}

// NewLogger creates a new logger instance
func NewLogger(writer io.Writer, level LogLevel, silent bool) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(writer, "", log.LstdFlags),
		silent: silent,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.silent || l.level > LogLevelDebug {
		return
	}
	l.logger.Printf("[DEBUG] "+format, args...)
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.silent || l.level > LogLevelInfo {
		return
	}
	l.logger.Printf("[INFO] "+format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.silent || l.level > LogLevelWarn {
		return
	}
	l.logger.Printf("[WARN] "+format, args...)
}

// Error logs an error message (always shown unless silent)
func (l *Logger) Error(format string, args ...interface{}) {
	if l.silent {
		return
	}
	l.logger.Printf("[ERROR] "+format, args...)
}

// Fatalf logs a fatal error and exits the program
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatalf("[FATAL] "+format, args...)
}

// Print prints a message without level prefix (for output)
func (l *Logger) Print(format string, args ...interface{}) {
	if l.silent {
		return
	}
	fmt.Fprintf(l.logger.Writer(), format, args...)
}

// DefaultLogger returns a logger configured for stderr
func DefaultLogger(silent bool) *Logger {
	return NewLogger(os.Stderr, LogLevelInfo, silent)
}

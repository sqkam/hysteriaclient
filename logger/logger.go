package logger

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logLevel  string = "debug"
	logFormat string = "console"
)
var zapLogger *zap.Logger

func init() {
	initLogger()
}

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	zapLogger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

type Logger interface {
	Trace(args ...any)
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
	Fatal(args ...any)
	Panic(args ...any)
}
type defaultLogger struct{}

func (l defaultLogger) Trace(args ...any) {
	args = append(args, "hysteriaClient")
	zapLogger.Debug(fmt.Sprint(args...))
}

func (l defaultLogger) Debug(args ...any) {
	zapLogger.Debug(fmt.Sprint(args...))
}

func (l defaultLogger) Info(args ...any) {
	zapLogger.Info(fmt.Sprint(args...))
}

func (l defaultLogger) Warn(args ...any) {
	zapLogger.Warn(fmt.Sprint(args...))
}

func (l defaultLogger) Error(args ...any) {
	zapLogger.Error(fmt.Sprint(args...))
}

func (l defaultLogger) Fatal(args ...any) {
	zapLogger.Fatal(fmt.Sprint(args...))
}

func (l defaultLogger) Panic(args ...any) {
	zapLogger.Panic(fmt.Sprint(args...))
}

var SingLogger Logger = defaultLogger{}

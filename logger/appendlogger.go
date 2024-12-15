package logger

import "fmt"

type appendLogger struct {
	l Logger
}

func NewAppendLogger(l Logger) Logger {
	return &appendLogger{l: l}
}

func (l appendLogger) Trace(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Debug(fmt.Sprint(args...))
}

func (l appendLogger) Debug(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Debug(fmt.Sprint(args...))
}

func (l appendLogger) Info(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Info(fmt.Sprint(args...))
}

func (l appendLogger) Warn(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Warn(fmt.Sprint(args...))
}

func (l appendLogger) Error(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Error(fmt.Sprint(args...))
}

func (l appendLogger) Fatal(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Fatal(fmt.Sprint(args...))
}

func (l appendLogger) Panic(args ...any) {
	args = append(args, "hysteriaClient")
	l.l.Panic(fmt.Sprint(args...))
}

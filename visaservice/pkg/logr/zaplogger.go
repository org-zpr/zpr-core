package logr

import (
	"go.uber.org/zap"
)

type ZapLogger struct {
	sugar *zap.SugaredLogger
}

func NewZapLogger(base *zap.Logger) Logger {
	return &ZapLogger{base.Sugar()}
}

func (d *ZapLogger) DPanic(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.DPanic(msg)
	} else {
		d.sugar.DPanicw(msg, args...)
	}
}

func (d *ZapLogger) DPanicm(msg string) {
	d.sugar.DPanic(msg)
}

func (d *ZapLogger) DPanicf(template string, args ...interface{}) {
	d.sugar.DPanicf(template, args...)
}

func (d *ZapLogger) Panic(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.Panic(msg)
	} else {
		d.sugar.Panicw(msg, args...)
	}
}

func (d *ZapLogger) Panicm(msg string) {
	d.sugar.Panic(msg)
}

func (d *ZapLogger) Panicf(template string, args ...interface{}) {
	d.sugar.Panicf(template, args...)
}

func (d *ZapLogger) Error(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.Error(msg)
	} else {
		d.sugar.Errorw(msg, args...)
	}
}

func (d *ZapLogger) Errorm(msg string) {
	d.sugar.Error(msg)
}

func (d *ZapLogger) Errorf(template string, args ...interface{}) {
	d.sugar.Errorf(template, args...)
}

func (d *ZapLogger) Warn(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.Warn(msg)
	} else {
		d.sugar.Warnw(msg, args...)
	}
}

func (d *ZapLogger) Warnm(msg string) {
	d.sugar.Warn(msg)
}

func (d *ZapLogger) Warnf(template string, args ...interface{}) {
	d.sugar.Warnf(template, args...)
}

func (d *ZapLogger) Info(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.Info(msg)
	} else {
		d.sugar.Infow(msg, args...)
	}
}

func (d *ZapLogger) Infom(msg string) {
	d.sugar.Info(msg)
}

func (d *ZapLogger) Infof(template string, args ...interface{}) {
	d.sugar.Infof(template, args...)
}

func (d *ZapLogger) Debug(msg string, args ...interface{}) {
	if len(args) == 0 {
		d.sugar.Debug(msg)
	} else {
		d.sugar.Debugw(msg, args...)
	}
}

func (d *ZapLogger) Debugm(msg string) {
	d.sugar.Debug(msg)
}

func (d *ZapLogger) Debugf(template string, args ...interface{}) {
	d.sugar.Debugf(template, args...)
}

func (d *ZapLogger) With(args ...interface{}) Logger {
	return &ZapLogger{d.sugar.With(args...)}
}

func (d *ZapLogger) WithError(err error) Logger {
	return &ZapLogger{d.sugar.With("error", err)}
}

func (d *ZapLogger) Sync() {
	d.sugar.Sync()
}

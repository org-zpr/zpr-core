package logr

// Logger logging interface for surenet
type Logger interface {
	DPanic(msg string, kvargs ...interface{})
	DPanicm(msg string)
	DPanicf(template string, args ...interface{})

	Panic(msg string, kvargs ...interface{})
	Panicm(msg string)
	Panicf(template string, args ...interface{})

	Error(msg string, kvargs ...interface{})
	Errorm(msg string)
	Errorf(template string, args ...interface{})

	Warn(msg string, kvargs ...interface{})
	Warnm(msg string)
	Warnf(template string, args ...interface{})

	Info(msg string, kvargs ...interface{})
	Infom(msg string)
	Infof(template string, args ...interface{})

	Debug(msg string, args ...interface{})
	Debugm(msg string)
	Debugf(template string, args ...interface{})

	With(args ...interface{}) Logger
	WithError(err error) Logger

	Sync()
}

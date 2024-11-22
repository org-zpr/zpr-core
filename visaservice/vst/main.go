// The visa service test tool.
//
// This may eventually have a more complex command line interface to allow user
// to pick types of test to run.  There are many different types of tests that
// could be run.  For example:
//
// 1. test the admin API HTTP interface of a visa service
//
// 2. test the initial node registration
//
// 2.1 does challenge change each time?
//
// 2.2 does session id change?
//
// 2.3 does visa service timeout if we don't do anything?
//
// 2.4 test sending back the wrong information, should fail.
//
// 3. test the visa service's ability to handle a large number of visa requests, or connects or disconnects, etc.
//
// 4. tests for ability to handle oddities in the node registration process.
//
// 5. tests for the TLS over the admin interface (if we are expecting CA signed cert)
//
// TODO: more here as I think of them
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"zpr.org/vst/pkg/conform"
)

func main() {
	app := &cli.App{
		Name:      "vst",
		Usage:     "ZPR visa service test tool",
		UsageText: "vst [options] <visa-service-address> <node-certificate-file>",
		Flags: []cli.Flag{
			&cli.UintFlag{
				Name:    "admin_port",
				Aliases: []string{"a"},
				Usage:   "visa service admin port (HTTPS)",
				Value:   8182,
			},
			&cli.UintFlag{
				Name:    "vs_port",
				Aliases: []string{"v"},
				Usage:   "visa service port (THRIFT)",
				Value:   5002,
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "verbose run with more verbosity and displays log on stderr",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {
			if c.Args().Len() < 2 {
				fmt.Fprintf(os.Stderr, "usage: %s\n", c.App.UsageText)
				return fmt.Errorf("argument error")
			}
			adminAddr := netip.AddrPortFrom(netip.MustParseAddr(c.Args().Get(0)), uint16(c.Uint("admin_port")))
			vsAddr := netip.AddrPortFrom(netip.MustParseAddr(c.Args().Get(0)), uint16(c.Uint("vs_port")))
			nodeCert, err := loadCertFromPEMFile(c.Args().Get(1))
			if err != nil {
				return err
			}
			return start(adminAddr, vsAddr, nodeCert, c.Bool("verbose"))
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "🤖 error: %v\n", err)
		os.Exit(1)
	}
}

func start(adminAddr, vsAddr netip.AddrPort, nodeCert *x509.Certificate, verbose bool) error {
	zlog := func() *zap.SugaredLogger {
		zl, err := initLogging(verbose, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize log system: %v\n", err)
			os.Exit(1)
		}
		return zl.Sugar()
	}()

	zlog.Info("visaservice test starting")
	defer zlog.Info("visaservice test finished")

	card, err := conform.RunTests(conform.TestsToRun, vsAddr, adminAddr, nodeCert, zlog.Desugar())
	if card != nil {
		fmt.Println()
		card.Print()
		fmt.Println()
	}
	return err
}

func loadCertFromPEMFile(path string) (*x509.Certificate, error) {
	pemdata, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read node certificate file: %v", err)
	}
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("failed to parse node certificate file: no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func initLogging(verbose bool, devMode bool) (*zap.Logger, error) {
	lev := zapcore.InfoLevel
	if verbose {
		lev = zapcore.DebugLevel
		devMode = true
	}

	zapEnc := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,     // zapcore.EpochTimeEncoder
		EncodeDuration: zapcore.SecondsDurationEncoder, // zapcore.StringDurationEncoder
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	zapC := zap.Config{
		Level:             zap.NewAtomicLevelAt(lev),
		Development:       devMode,
		DisableCaller:     true,
		DisableStacktrace: false, // no stack traces
		EncoderConfig:     zapEnc,
		ErrorOutputPaths:  []string{"stderr"},
	}
	if devMode {
		zapC.Encoding = "console"
	} else {
		zapC.Encoding = "json"
	}
	if verbose {
		zapC.OutputPaths = []string{"stderr"}
	} else {
		zapC.OutputPaths = []string{"vst.log"}
	}
	logger, err := zapC.Build()
	if err != nil {
		return nil, err
	}
	return logger, nil
}

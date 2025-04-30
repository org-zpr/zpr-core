package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-version"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice"
)

const (
	versionMajor = 0
	versionMinor = 1
	versionPatch = 0

	// Default Max lifetime for authenticated. When they expire we require
	// re-auth from the peer. For milestone two we do not have real auth
	// or re-auth, so this is set high.
	DefaultMaxAuthDuration = 24 * time.Hour

	// The bootstrap auth is used while we are bringing up a visa service
	// and is also used for the expiration time of temporary visas issued
	// to nodes prior to auth.  Again, this is set artifically high for
	// milestone 2.
	DefaultBootstrapAuthDuration = DefaultMaxAuthDuration
)

var (
	BuildVersion string
	serviceLog   logr.Logger
)

func main() {
	var err error
	ver := MustSetVersion(BuildVersion)

	app := cli.NewApp()
	app.Version = ver.String()
	app.Name = "vserivce"
	app.Usage = "runs a ZPR visa service"
	app.UsageText = `vservice [global options]

Starts the ZPR visa service and admin service. Before starting this there must
already be an adapter running and connected to a ZPR node using the visa
service credentials. Once this starts the node will register with this visa
service using the visa service API.
	`

	app.Authors = []*cli.Author{
		{
			Name:  "The Amazing ZPR Team",
			Email: "zpr@ai.co",
		},
	}

	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "verbose",
			Usage: "enable verbose/debug logging",
		},
		&cli.StringFlag{
			Name:    "conf",
			Aliases: []string{"c"},
			Value:   "config.yaml",
			Usage:   "load configuration from `FILE`",
		},
		&cli.StringFlag{
			Name:     "policy",
			Aliases:  []string{"p"},
			Required: true,
			Usage:    "use initial ZPL policy in `FILE`",
		},
		&cli.StringFlag{
			Name:  "issuer",
			Usage: "use `NAME` as the issuer on any tokens created by the service",
		},
		&cli.StringFlag{
			Name:    "listen_addr",
			Aliases: []string{"l"},
			Usage:   "override the default visa service listen address with `HOST:PORT`",
		},
		&cli.IntFlag{
			Name:  "admin_port",
			Usage: "override the default admin service port with `PORT`",
		},
	}

	app.Action = func(c *cli.Context) error {

		config, err := vservice.LoadConfig(c.String("conf"))
		if err != nil {
			return fmt.Errorf("configuration file parse error: %w", err)
		}
		verbose := config.IsVerbose() || c.Bool("verbose")
		devMode := true
		serviceLog, err = initLogging(verbose, devMode)
		if err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}

		cert, err := tls.LoadX509KeyPair(config.VSCert, config.VSKey)
		if err != nil {
			return fmt.Errorf("failed to initialize visa service transport credentials from %v: %w", config.VSCert, err)
		}
		tconfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		a_cert, err := loadCertFromFile(config.AdapterCert)
		if err != nil {
			return fmt.Errorf("failed to load adapter certificate: %w", err)
		}
		cn := a_cert.Subject.CommonName

		authorityCert, err := loadCertFromFile(config.AuthorityCert)
		if err != nil {
			return fmt.Errorf("failed to load authority certificate: %w", err)
		}

		pidf, err := NewPidFile("vservice")
		if err != nil {
			serviceLog.WithError(err).Warnm("failed to write pid file")
		} else {
			defer pidf.Remove()
		}

		sigChan := make(chan os.Signal, 4)
		signal.Notify(sigChan, os.Interrupt)
		defer close(sigChan)
		sigExitChan := make(chan struct{})

		jwtpk, err := snauth.LoadRSAKeyFromFile(config.VSKey)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		maxAuthDuration := DefaultMaxAuthDuration             // TODO: from config or command line
		bootstrapAuthDuration := DefaultBootstrapAuthDuration // TODO: from config or command line
		service, err := vservice.NewVisaService(c.String("policy"), cn, jwtpk, tconfig, bootstrapAuthDuration, maxAuthDuration, authorityCert, serviceLog)
		if err != nil {
			return fmt.Errorf("failed to create visa service: %w", err)
		}

		go func() {
			select {
			case <-sigChan:
				serviceLog.Infom("interrupt signal, now aborting")
				service.Stop()
				time.Sleep(1 * time.Second)

			case <-sigExitChan:
				serviceLog.Infom("visa service exited")
				return
			}
		}()

		issuerName := c.String("issuer")
		if issuerName == "" {
			issuerName = uuid.New().String()
		}

		var vsAddr netip.Addr
		var vsPort, adminPort uint16

		if listenAddr := c.String("listen_addr"); listenAddr != "" {
			ap, err := netip.ParseAddrPort(listenAddr)
			if err != nil {
				return fmt.Errorf("failed to parse listen address: %w", err)
			}
			vsAddr = ap.Addr()
			vsPort = ap.Port()
		} else {
			vsAddr = netip.MustParseAddr(vservice.VisaServiceAddress)
			vsPort = vservice.VisaServicePort
		}

		if adminPort = uint16(c.Int("admin_port")); adminPort == 0 {
			adminPort = vservice.AdminPort // constant
		}

		err = service.Start(issuerName, vsAddr, vsPort, adminPort) // Blocking!
		close(sigExitChan)

		return err
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		if serviceLog != nil {
			serviceLog.WithError(err).Error("visa service exited with error")
		}
		os.Exit(1)
	}
	if serviceLog != nil {
		serviceLog.Infom("visa service has exited")
		serviceLog.Sync()
	}
}

func loadCertFromFile(certFile string) (*x509.Certificate, error) {
	pemdata, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	blk, _ := pem.Decode(pemdata)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// This initLogging function copied from the ZPR node code.
func initLogging(verbose bool, devMode bool) (logr.Logger, error) {
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

	lev := zapcore.InfoLevel
	if verbose {
		lev = zapcore.DebugLevel
	}
	zapC := zap.Config{
		Level:             zap.NewAtomicLevelAt(lev),
		Development:       false,
		DisableCaller:     true,
		DisableStacktrace: false, // no stack traces
		EncoderConfig:     zapEnc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	if devMode {
		zapC.Encoding = "console"
	} else {
		zapC.Encoding = "json"
		// This setup is copied from zap ProcuctionConfig setting. I have no
		// idea what these numbers mean...
		// In dev mode there is no sampling.
		zapC.Sampling = &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		}
	}
	logger, err := zapC.Build()
	if err != nil {
		return nil, err
	}
	return logr.NewZapLogger(logger), nil
}

func MustSetVersion(buildVersion string) *version.Version {
	var err error
	var ver *version.Version
	if buildVersion != "" {
		if ver, err = version.NewSemver(fmt.Sprintf("%d.%d.%d-%v", versionMajor, versionMinor, versionPatch, buildVersion)); err != nil {
			panic(err)
		}
	} else {
		ver, _ = version.NewSemver(fmt.Sprintf("%d.%d.%d", versionMajor, versionMinor, versionPatch))
	}
	return ver
}

type PidFile struct {
	fpath string
}

// NewPidFile writes a pid file in the default location.
func NewPidFile(appname string) (*PidFile, error) {
	datadir := os.Getenv("XDG_DATA_HOME")
	if datadir == "" {
		datadir = os.Getenv("HOME")
		if datadir == "" {
			datadir = "/var/run"
		} else {
			datadir = filepath.Join(datadir, ".local", "share")
		}
	}
	fpath := filepath.Join(datadir, "zpr", "vservice.pid")
	odir := filepath.Dir(fpath)
	if err := os.MkdirAll(odir, 0755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(fpath); os.IsNotExist(err) {
		if err := os.WriteFile(fpath, []byte(fmt.Sprintf("%v", os.Getpid())), 0644); err != nil {
			return nil, err
		}
		return &PidFile{fpath}, nil
	}
	return nil, fmt.Errorf("file in the way: %v", fpath)
}

// Remove removes existing pid file.
func (p *PidFile) Remove() error {
	return os.Remove(p.fpath)
}

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/credentials"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice"
)

const (
	versionMajor = 0
	versionMinor = 1
	versionPatch = 0

	PIDDir = "/var/run/zpr"

	// Default Max lifetime for authenticated. When they expire we require
	// re-auth from the peer.
	DefaultMaxAuthDuration = 6 * time.Hour
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

	More details TBD.
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
			Name:     "tlsname",
			Required: false,
			Usage:    "TLS `FQDN` used when talking to the visa service (must match certificate). Also overrides vs_domain in config file.",
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

		// These credentials are only used to check the server.
		// Possibly we can include a client credential too.  See docs for NewClientTLSFromFile.
		// And not sure what needs to happen on grpc server start side.
		// ZPR itself should lock down access to the grpc VSS service to this single adapter.
		// BUT might be nice to have a creds layer on top of that too, but not sure if that is greater
		// security since presumably whoever is on this host trying to talk to the VSS service also
		// would have access to whatever creds file we are using here.
		vssTransportCreds, err := credentials.NewClientTLSFromFile(config.VSSClientCert, "")
		if err != nil {
			return fmt.Errorf("failed to initialize visa support service transport credentials from %v: %w", config.VSSClientCert, err)
		}

		vsTransportCreds, err := credentials.NewServerTLSFromFile(config.VSCert, config.VSKey) // uses sn_certificate & key (like node)
		if err != nil {
			return fmt.Errorf("failed to initialize visa service transport credentials from %v: %w", config.VSCert, err)
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

		maxAuthDuration := DefaultMaxAuthDuration // TODO: add a command line arg for this
		service, err := vservice.NewVisaService(c.String("policy"), jwtpk, vssTransportCreds, vsTransportCreds, maxAuthDuration, serviceLog)
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

		var vsdnsname string
		if c.String("tlsname") != "" {
			vsdnsname = c.String("tlsname")
		} else {
			// TODO: In the future our name should be determined by our ZPR address.
			// I think each visa service needs its own name, but am not actually sure.
			if hostname, err := os.Hostname(); err != nil {
				vsdnsname = fmt.Sprintf("%s.%s", hostname, config.VSDomain)
			} else {
				vsdnsname = fmt.Sprintf("vs.%s", config.VSDomain)
			}
		}
		err = service.Start(supportAddr, config.VSSSan, vsdnsname, vservice.VisaServicePort) // Blocking!
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
		Development:       devMode,
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
	fpath := filepath.Join(PIDDir, "visaservice.pid")
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

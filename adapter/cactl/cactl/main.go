package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"zpr.org/cactl/internal/ipc"

	"github.com/labstack/gommon/color"
	"github.com/urfave/cli/v2"
)

const VERSION = "0.0.1-beta"

const CD_CONTROL_SOCKET_NAME = "cd.sock"

func main() {
	app := &cli.App{
		Name:    "cactl",
		Usage:   "ZPR client adapter control",
		Version: VERSION,
		Commands: []*cli.Command{
			connectCmd(),
			statusCmd(),
			disconnectCmd(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(color.Red(err.Error()))
		os.Exit(0)
	}
}

func get_control_socket() string {
	dd := os.Getenv("XDG_DATA_HOME")
	if dd == "" {
		dd = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}
	return filepath.Join(dd, "zpr", CD_CONTROL_SOCKET_NAME)
}

func connectCmd() *cli.Command {
	return &cli.Command{
		Name:      "connect",
		Usage:     "Connect to a ZPR network",
		UsageText: "cactl connect ( CONFIG_FILE | CONFIG_NAME )",
		Action: func(c *cli.Context) error {
			configName := c.Args().Get(0)
			if configName == "" {
				return errors.New("missing configuration name")
			}
			connectArg := configName
			if strings.HasSuffix(configName, ".toml") || strings.HasPrefix(configName, ".") || strings.HasPrefix(configName, "/") {
				cpath, err := filepath.Abs(configName)
				if err != nil {
					fmt.Print(color.Red("failed to parse configuration path"))
					fmt.Println("  {}", err)
					return nil
				}
				connectArg = cpath
			}
			ctl, err := ipc.NewCDCtl(get_control_socket())
			if err != nil {
				return err
			}
			result, err := ctl.Connect(connectArg)
			if err != nil {
				return err
			}
			if result.IsError {
				fmt.Println(color.Red(result.Message()))
			} else {
				fmt.Println(color.Green(result.Message()))
			}

			return nil
		},
	}
}

func statusCmd() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Show status of active ZPR connections",
		Action: func(c *cli.Context) error {
			ctl, err := ipc.NewCDCtl(get_control_socket())
			if err != nil {
				return err
			}
			result, err := ctl.Status()
			if err != nil {
				return err
			}
			if result.IsError {
				fmt.Println(color.Red(result.Message()))
			} else {
				fmt.Println(color.Green(result.Message()))
			}
			return nil
		},
	}
}

func disconnectCmd() *cli.Command {
	return &cli.Command{
		Name:      "disconnect",
		Usage:     "Disconnect from ZPR networks",
		UsageText: "cactl disconnect [ CONFIG_NAME ]",
		Action: func(c *cli.Context) error {
			configName := c.Args().Get(0)
			ctl, err := ipc.NewCDCtl(get_control_socket())
			if err != nil {
				return err
			}
			result, err := ctl.Disconnect(configName)
			if err != nil {
				return err
			}
			if result.IsError {
				fmt.Println(color.Red(result.Message()))
			} else {
				fmt.Println(color.Green(result.Message()))
			}
			return nil
		},
	}
}

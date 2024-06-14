package vservice

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type VSConfig struct {
	VSSClientCert string `yaml:"vss_client_cert,omitempty"`
	VSSSan        string `yaml:"vss_san,omitempty"`
	VSCert        string `yaml:"vs_cert,omitempty"`
	VSKey         string `yaml:"vs_key,omitempty"`
	VSDomain      string `yaml:"vs_domain,omitempty"`
	Verbose       bool   `yaml:"verbose,omitempty"`
	NodeAddr      string `yaml:"node_addr,omitempty"` // use GetNodeAddr() to get netip.Addr

	source   string
	nodeAddr netip.Addr
}

func LoadConfig(filename string) (*VSConfig, error) {
	var config VSConfig
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return nil, fmt.Errorf("syntax error: %v", err)
	}
	config.source, err = func() (string, error) {
		if filepath.IsAbs(filename) {
			return filename, nil
		}
		abspath, err := filepath.Abs(filename)
		if err != nil {
			return "", err
		}
		return abspath, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("cannot get absolute path for %q: %v", filename, err)
	}
	if err = config.check(); err != nil {
		return nil, err
	}
	return &config, nil
}

// Check the configuration values and also set any derived values.
func (c *VSConfig) check() error {
	var err error
	c.nodeAddr, err = netip.ParseAddr(c.NodeAddr)
	if err != nil {
		return fmt.Errorf("invalid node_addr: %v", c.NodeAddr)
	}

	c.VSSClientCert, err = c.fixPath(c.VSSClientCert, true)
	if err != nil {
		return fmt.Errorf("invalid vss_client_cert: %v", err)
	}

	c.VSCert, err = c.fixPath(c.VSCert, true)
	if err != nil {
		return fmt.Errorf("invalid vs_cert: %v", err)
	}

	c.VSKey, err = c.fixPath(c.VSKey, true)
	if err != nil {
		return fmt.Errorf("invalid vs_key: %v", err)
	}
	if c.VSDomain == "" {
		return fmt.Errorf("vs_domain cannot be empty")
	}
	return nil
}

func (c *VSConfig) IsVerbose() bool {
	return c.Verbose
}

func (c *VSConfig) GetNodeAddr() netip.Addr {
	return c.nodeAddr
}

func (c *VSConfig) fixPath(path string, required bool) (string, error) {
	var newP string
	if path == "" {
		if required {
			return "", fmt.Errorf("cannot be empty")
		}
		return path, nil
	}

	base := filepath.Dir(c.source)

	if !filepath.IsAbs(path) {
		newP = filepath.Join(base, path)
	} else {
		newP = path
	}
	if _, err := os.Stat(newP); err != nil {
		return newP, err
	}
	return newP, nil
}

package vservice

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type VSConfig struct {
	// The (noise) certificate used by the visa service adapter.
	// Used to obtain the correct CN for visa service bootstrap actor.
	AdapterCert string `yaml:"adapter_cert,omitempty"`

	// The authority cert is used to check (noise) certificate signatures.
	AuthorityCert string `yaml:"root_ca,omitempty"`

	// The VSCert/VSKey keypair are used for:
	//   - The admin service gRPC TLS session.
	//   - Signing all the JWT auth tokens we create.
	//   - Checking the signature on a policy file
	//   - (and not yet for..) the thrift connection
	//
	// This key usage nightmare is left over from prototype and needs to be
	// re-worked.
	VSCert string `yaml:"vs_cert,omitempty"`
	VSKey  string `yaml:"vs_key,omitempty"`

	Verbose bool `yaml:"verbose,omitempty"`

	source string
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

	c.VSCert, err = c.fixPath(c.VSCert, true)
	if err != nil {
		return fmt.Errorf("invalid vs_cert: %w", err)
	}

	c.AuthorityCert, err = c.fixPath(c.AuthorityCert, true)
	if err != nil {
		return fmt.Errorf("invalid authority_cert: %w", err)
	}

	c.VSKey, err = c.fixPath(c.VSKey, true)
	if err != nil {
		return fmt.Errorf("invalid vs_key: %w", err)
	}

	c.AdapterCert, err = c.fixPath(c.AdapterCert, true)
	if err != nil {
		return fmt.Errorf("invalid adapter_cert: %w", err)
	}
	return nil
}

func (c *VSConfig) IsVerbose() bool {
	return c.Verbose
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

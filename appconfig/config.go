package appconfig

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/femnad/mare"
	marecmd "github.com/femnad/mare/cmd"
)

const (
	clientIdEnv     = "SPOTIFY_ID"
	clientSecretEnv = "SPOTIFY_SECRET"
)

type AuthConfig struct {
	ClientIdStr     string `yaml:"client_id"`
	ClientIdCmd     string `yaml:"client_id_cmd"`
	ClientSecretStr string `yaml:"client_secret"`
	ClientSecretCmd string `yaml:"client_secret_cmd"`
	RedirectURI     string `yaml:"redirect_uri"`
}

type Config struct {
	Auth AuthConfig `yaml:"auth"`
}

func isInEnv(key string) bool {
	_, exists := os.LookupEnv(key)
	return exists
}

func fromCmdOrConfig(cmd, fallback string) (string, error) {
	if cmd != "" {
		in := marecmd.Input{Command: cmd}
		out, err := marecmd.RunFormatError(in)
		if err != nil {
			return "", err
		}

		return strings.TrimSpace(out.Stdout), nil
	}

	return fallback, nil
}

func (cfg Config) url() (*url.URL, error) {
	redirectURI := cfg.Auth.RedirectURI
	if redirectURI == "" {
		return nil, fmt.Errorf("empty URL given for redirect URI")
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL from %s: %v", redirectURI, err)
	}

	return u, nil
}

func (cfg Config) Port() (string, error) {
	var dummyPort string

	u, err := cfg.url()
	if err != nil {
		return dummyPort, err
	}

	return u.Port(), nil
}

func (cfg Config) Path() (string, error) {
	var dummyPath string

	u, err := cfg.url()
	if err != nil {
		return dummyPath, err
	}

	return u.Path, nil
}

func (cfg Config) ClientIdInEnv() bool {
	return isInEnv(clientIdEnv)
}

func (cfg Config) ClientSecretInEnv() bool {
	return isInEnv(clientSecretEnv)
}

func (cfg Config) ClientId() (string, error) {
	return fromCmdOrConfig(cfg.Auth.ClientIdCmd, cfg.Auth.ClientIdStr)
}

func (cfg Config) ClientSecret() (string, error) {
	return fromCmdOrConfig(cfg.Auth.ClientSecretCmd, cfg.Auth.ClientSecretStr)
}

func (cfg Config) RedirectURI() string {
	return cfg.Auth.RedirectURI
}

func Get(configFile string) (Config, error) {
	var cfg Config

	configFile = mare.ExpandUser(configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg, fmt.Errorf("error reading config file %s: %v", configFile, err)
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("error unmarshalling config file %s: %v", configFile, err)
	}

	return cfg, nil
}

package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config represents the global service configuration.
type Config struct {
	Listen                          string                            `mapstructure:"listen"`
	WorkDir                         string                            `mapstructure:"workDir"`
	MaxConcurrentRequests           int                               `mapstructure:"maxConcurrentRequests"`
	PKCS11Module                    string                            `mapstructure:"pkcs11Module"`
	APIKeyHMACSecret                string                            `mapstructure:"apiKeyHMACSecret"`
	APIKeys                         []string                          `mapstructure:"apiKeys"`
	RequestSigningTimestampSkewSecs int                               `mapstructure:"requestSigningTimestampSkewSeconds"`
	LogLevel                        string                            `mapstructure:"logLevel"`
	Profiles                        map[string]SignProfile            `mapstructure:"profiles"`
	PasswordProviders               map[string]PasswordProviderConfig `mapstructure:"passwordProviders"`
}

// SignProfile defines how a specific artifact should be signed.
type SignProfile struct {
	Certificate    CertificateConfig `mapstructure:"certificate"`
	Timestamper    TimestampConfig   `mapstructure:"timestamper"`
	Description    string            `mapstructure:"description"`
	DescriptionURL string            `mapstructure:"description_url"`
	AskPass        bool              `mapstructure:"askPass"`
}

// CertificateConfig holds information about the certificate/key.
type CertificateConfig struct {
	Type             string `mapstructure:"type"`
	Certs            string `mapstructure:"certs"`                      // Certificate file path (PEM for type=file or type=pkcs11)
	Key              string `mapstructure:"key"`                        // Key URI/path (PKCS#11 URI for type=pkcs11, file path otherwise)
	PasswordProvider string `mapstructure:"passwordProvider,omitempty"` // Name of a passwordProviders entry
	PKCS11Module     string `mapstructure:"pkcs11Module,omitempty"`     // Path to the PKCS#11 module .so
	PKCS11Engine     string `mapstructure:"pkcs11Engine,omitempty"`     // Path to the OpenSSL PKCS#11 engine .so
}

// TimestampConfig defines the RFC3161 timestamp server(s).
type TimestampConfig struct {
	Type string   `mapstructure:"type"`
	URLs []string `mapstructure:"urls"`
}

// PasswordProviderConfig holds settings for different PIN retrieval methods.
type PasswordProviderConfig struct {
	Type   string            `mapstructure:"type"`
	Config map[string]string `mapstructure:"config"`
}

// LoadConfig reads the configuration from the specified path and validates it.
func LoadConfig(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// validate performs semantic validation of the loaded configuration.
func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address must be specified")
	}
	if c.WorkDir == "" {
		return fmt.Errorf("workDir must be specified")
	}
	if c.PKCS11Module == "" {
		return fmt.Errorf("pkcs11Module path must be specified")
	}
	if c.APIKeyHMACSecret == "" {
		return fmt.Errorf("apiKeyHMACSecret path must be specified")
	}

	// Check if HMAC secret file exists
	if _, err := os.Stat(c.APIKeyHMACSecret); err != nil {
		return fmt.Errorf("apiKeyHMACSecret file error: %w", err)
	}

	return nil
}

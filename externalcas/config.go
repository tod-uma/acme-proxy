package externalcas

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Configuration bits for a DNS provider as per Lego docs
type legoConfig struct {
	Provider       string            `json:"provider"`
	DnsServersList []string          `json:"dns_servers"`
	Env_Vars       map[string]string `json:"env_vars"`
}

type metrics struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Port       int    `json:"port,omitempty"`
	DataSource string `json:"dataSource,omitempty"`
}

// AcmeProxyConfig contains the configuration for connecting to an external ACME CA
type acmeProxyConfig struct {
	// ACME directory url of External CA (required)
	CaURL string `json:"ca_url"`

	// External Account Binding
	Email string `json:"account_email,omitempty"`

	Kid     string `json:"eab_kid"`
	HmacKey string `json:"eab_hmac_key"`

	// Certificate lifetime in days (optional)
	CertLifetime int `json:"certlifetime,omitempty"`

	// Upper bound, in seconds, on one certificate request to the upstream CA:
	// account registration, authorization, finalization and download (optional).
	// Zero means the default of 120 seconds.
	RequestTimeoutSeconds int `json:"request_timeout,omitempty"`

	// How long, in seconds, lego polls the upstream order for the issued
	// certificate after finalization (optional). Zero means lego's default of
	// 30 seconds. CAs that validate many SANs per order may need longer.
	CertificateTimeoutSeconds int `json:"certificate_timeout,omitempty"`

	// Lego provider connection variables for dns01 TXT challenge
	Lego legoConfig `json:"dns01_txt"`

	// Prometheus metrics endpoint (optional)
	Metrics metrics `json:"metrics"`

	// derived during Validate(); not marshaled
	useEAB   bool
	useDNS01 bool
}

// Validate checks if the values provided in ca.json file contain required fields
// and valid values after they are unmarshalled into `acmeProxyConfig`
func (c *acmeProxyConfig) Validate() error {
	if c.CaURL == "" {
		return errors.New("ca_url is required")
	}
	if c.Kid != "" && c.HmacKey != "" {
		c.useEAB = true
	}
	if c.Lego.Provider != "" && len(c.Lego.Env_Vars) != 0 {
		c.useDNS01 = true
	}

	if !c.useEAB && !c.useDNS01 {
		return errors.New("missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration")
	}
	if c.CertLifetime < 0 {
		return errors.New("certlifetime cannot be negative")
	}
	if c.RequestTimeoutSeconds < 0 {
		return errors.New("request_timeout cannot be negative")
	}
	if c.CertificateTimeoutSeconds < 0 {
		return errors.New("certificate_timeout cannot be negative")
	}
	if c.CertificateTimeout() >= c.RequestTimeout() {
		return fmt.Errorf("certificate_timeout (%s) must be less than request_timeout (%s)",
			c.CertificateTimeout(), c.RequestTimeout())
	}

	// Consider Metrics enabled only when port & datasource both are defined
	if c.Metrics.Port > 0 && c.Metrics.DataSource != "" {
		c.Metrics.Enabled = true
	}

	if (c.Metrics.Port > 0 && c.Metrics.DataSource == "") || (c.Metrics.Port == 0 && c.Metrics.DataSource != "") {
		return errors.New("invalid metrics port or dataSource.\nRefer docs https://software.es.net/acme-proxy/configuration")
	}
	return nil
}

// HTTPTimeout returns the timeout for HTTP client operations
func (c *acmeProxyConfig) HTTPTimeout() time.Duration {
	return 90 * time.Second
}

// RequestTimeout returns the timeout for one certificate request to the
// upstream CA: request_timeout seconds when set, otherwise 2 minutes.
func (c *acmeProxyConfig) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds > 0 {
		return time.Duration(c.RequestTimeoutSeconds) * time.Second
	}
	return 2 * time.Minute
}

// CertificateTimeout returns how long lego polls the upstream order for the
// issued certificate after finalization: certificate_timeout seconds when
// set, otherwise lego's own default of 30 seconds.
func (c *acmeProxyConfig) CertificateTimeout() time.Duration {
	if c.CertificateTimeoutSeconds > 0 {
		return time.Duration(c.CertificateTimeoutSeconds) * time.Second
	}
	return 30 * time.Second
}

// parseConfig is a helper function which reads ca.json file as rawjson and validates
// acme-proxy specific configuration bits under the `authority` section of the config
func parseConfig(raw json.RawMessage) (*acmeProxyConfig, error) {
	var cfg acmeProxyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

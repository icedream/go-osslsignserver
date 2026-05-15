package bootstrap

import (
	"fmt"
	"os"

	ginDefault "github.com/gin-gonic/gin"
	"github.com/icedream/go-osslsignserver/internal/api/gin"
	"github.com/icedream/go-osslsignserver/internal/api/gin/server"
	"github.com/icedream/go-osslsignserver/internal/config"
	mockpkcs11 "github.com/icedream/go-osslsignserver/internal/mock/pkcs11"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/icedream/go-osslsignserver/internal/password"
	"github.com/icedream/go-osslsignserver/internal/profiles"
	"github.com/icedream/go-osslsignserver/internal/signing"
	"github.com/miekg/pkcs11"
	"github.com/spf13/viper"
)

// Config holds all application configuration and initialized services.
type Config struct {
	SigningService    *signing.Service
	PasswordProviders map[string]password.Provider
	Router            *ginDefault.Engine
}

// Initialize creates and wires all application components.
func Initialize(cfg *config.Config) (*Config, error) {
	// Initialize all configured password providers by name.
	pwProviders, err := initializePasswordProviders(cfg.PasswordProviders, cfg.Profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize password providers: %w", err)
	}

	// For each PKCS#11 profile, validate the PIN against the token at startup.
	// Interactive providers (prompt/terminal) will prompt once here and cache the PIN.
	for profileName, profileConfig := range cfg.Profiles {
		if profileConfig.Certificate.Type != "pkcs11" {
			continue
		}
		providerName := profileConfig.Certificate.PasswordProvider
		if providerName == "" {
			continue
		}
		prov, ok := pwProviders[providerName]
		if !ok {
			return nil, fmt.Errorf("profile '%s' references unknown password provider '%s'", profileName, providerName)
		}
		modulePath := profileConfig.Certificate.PKCS11Module
		if modulePath == "" {
			modulePath = cfg.PKCS11Module
		}
		if modulePath == "" {
			return nil, fmt.Errorf("profile '%s': pkcs11Module must be specified", profileName)
		}
		if err := validatePINAgainstToken(prov, modulePath); err != nil {
			return nil, fmt.Errorf("PIN validation failed for profile '%s': %w", profileName, err)
		}
	}

	// Initialize signing service
	profilesMap, err := initializeProfiles(cfg, pwProviders)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize profiles: %w", err)
	}

	executor := osslsigncode.New()

	// Ensure work directory exists
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	signingService := signing.NewService(cfg, executor, profilesMap)

	// Initialize request signing authentication
	if err := gin.SetRequestSigningSecret(cfg.APIKeyHMACSecret); err != nil {
		return nil, fmt.Errorf("failed to load request signing secret: %w", err)
	}

	// Set timestamp skew (default to 5 minutes if not specified)
	skewSecs := cfg.RequestSigningTimestampSkewSecs
	if skewSecs <= 0 {
		skewSecs = 300 // 5 minutes default
	}
	gin.SetTimestampSkew(skewSecs)

	// Create router with protected routes
	router := server.NewRouter(
		server.RouteGroup{
			Prefix: "/v1",
			Middleware: []ginDefault.HandlerFunc{
				gin.RequestSigningMiddleware(),
			},
			Routes: server.Routes{
				{
					Name:        "Sign",
					Method:      "POST",
					Pattern:     "/sign",
					HandlerFunc: server.Sign,
				},
			},
		},
		server.RouteGroup{
			Prefix:     "/v1",
			Middleware: []ginDefault.HandlerFunc{},
			Routes: server.Routes{
				{
					Name:        "Index",
					Method:      "GET",
					Pattern:     "/",
					HandlerFunc: server.Index,
				},
			},
		},
	)
	// Set signing service for handlers
	server.SetService(signingService)

	return &Config{
		SigningService:    signingService,
		PasswordProviders: pwProviders,
		Router:            router,
	}, nil
}

// validatePINAgainstToken validates the PIN by performing a C_Login call via PKCS#11.
// This ensures the PIN is correct before the service starts serving.
// The function accepts a PKCS#11 interface for testability.
func validatePINAgainstToken(provider password.Provider, modulePath string) error {
	// For actual usage, create a real PKCS#11 module
	// For testing, this will be mocked via the interface
	return validatePINAgainstTokenWithPKCS11(provider, modulePath, func(modulePath string) (*pkcs11.Ctx, error) {
		p := pkcs11.New(modulePath)
		if p == nil {
			return nil, fmt.Errorf("failed to create PKCS#11 module")
		}
		if err := p.Initialize(); err != nil {
			return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
		}
		return p, nil
	})
}

// validatePINAgainstTokenWithPKCS11 is an internal helper that accepts a PKCS#11 constructor
// for testability.
func validatePINAgainstTokenWithPKCS11(provider password.Provider, modulePath string, newPKCS11 func(string) (*pkcs11.Ctx, error)) error {
	p, err := newPKCS11(modulePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = p.Finalize()
		p.Destroy()
	}()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return fmt.Errorf("no PKCS#11 slots found")
	}

	// Try each slot to find one that matches the token
	var session pkcs11.SessionHandle
	for _, slot := range slots {
		session, err = p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			continue
		}
		defer func() { _ = p.CloseSession(session) }()

		// Get token info to check if it's the correct token
		_, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		// Request PIN from provider
		token, err := provider.RequestPassword(password.Request{Description: "PKCS#11 token login"})
		if err != nil {
			return fmt.Errorf("failed to request PIN: %w", err)
		}

		// Validate PIN
		report, err := provider.Progress(token)
		if err != nil {
			return fmt.Errorf("failed to progress PIN: %w", err)
		}

		// Open PIN enclave and attempt login
		pinBuf, err := report.Password.Open()
		if err != nil {
			return fmt.Errorf("failed to open PIN enclave: %w", err)
		}
		defer pinBuf.Destroy()

		err = p.Login(session, pkcs11.CKU_USER, string(pinBuf.Bytes()))
		if err == nil {
			// Login succeeded - logout and return success
			_ = p.Logout(session)
			return nil
		}
		// Login failed - try next slot
	}

	return fmt.Errorf("failed to login to any PKCS#11 token with provided PIN")
}

// validatePINAgainstTokenWithMock is an internal helper that accepts a MockPKCS11 for testing.
func validatePINAgainstTokenWithMock(provider password.Provider, mockModule *mockpkcs11.MockPKCS11) error {
	// Initialize the mock module
	if err := mockModule.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	slots, err := mockModule.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return fmt.Errorf("no PKCS#11 slots found")
	}

	// Try each slot to find one that matches the token
	for _, slot := range slots {
		session, err := mockModule.OpenSession(slot.ID, 0)
		if err != nil {
			continue
		}
		defer func() { _ = mockModule.CloseSession(session) }()

		// Get token info to check if it's the correct token
		_, err = mockModule.GetTokenInfo(slot.ID)
		if err != nil {
			continue
		}

		// Request PIN from provider
		token, err := provider.RequestPassword(password.Request{Description: "PKCS#11 token login"})
		if err != nil {
			return fmt.Errorf("failed to request PIN: %w", err)
		}

		// Validate PIN
		report, err := provider.Progress(token)
		if err != nil {
			return fmt.Errorf("failed to progress PIN: %w", err)
		}

		// Open PIN enclave and attempt login
		pinBuf, err := report.Password.Open()
		if err != nil {
			return fmt.Errorf("failed to open PIN enclave: %w", err)
		}
		defer pinBuf.Destroy()

		err = mockModule.LoginWithTracking(session, pkcs11.CKU_USER, string(pinBuf.Bytes()))
		if err == nil {
			// Login succeeded - logout and return success
			_ = mockModule.Logout(session)
			return nil
		}
		// Login failed - try next slot
	}

	return fmt.Errorf("failed to login to any PKCS#11 token with provided PIN")
}

// initializePasswordProviders instantiates the password providers that are actually
// referenced by at least one profile. Unreferenced entries in the config are ignored.
func initializePasswordProviders(providerConfig map[string]config.PasswordProviderConfig, profileConfigs map[string]config.SignProfile) (map[string]password.Provider, error) {
	// Collect the provider names actually needed.
	needed := make(map[string]struct{})
	for _, pc := range profileConfigs {
		if pc.Certificate.PasswordProvider != "" {
			needed[pc.Certificate.PasswordProvider] = struct{}{}
		}
	}

	result := make(map[string]password.Provider, len(needed))
	for name := range needed {
		pc, ok := providerConfig[name]
		if !ok {
			return nil, fmt.Errorf("password provider '%s' is referenced by a profile but not defined in passwordProviders", name)
		}
		v := viper.New()
		v.SetConfigType("yaml")
		v.Set("_name", name)
		for k, val := range pc.Config {
			v.Set(k, val)
		}
		prov, err := password.GetProvider(pc.Type, *v)
		if err != nil {
			return nil, fmt.Errorf("password provider '%s' (type %q): %w", name, pc.Type, err)
		}
		result[name] = prov
	}
	return result, nil
}

// parseCertificate parses a certificate from configuration.
func parseCertificate(certConfig config.CertificateConfig, cfg *config.Config) (osslsigncode.Certificate, error) {
	switch certConfig.Type {
	case "pkcs11":
		modulePath := certConfig.PKCS11Module
		if modulePath == "" {
			modulePath = cfg.PKCS11Module
		}
		if modulePath == "" {
			return nil, fmt.Errorf("pkcs11Module must be specified for PKCS#11 certificates")
		}
		if certConfig.Key == "" {
			return nil, fmt.Errorf("key (PKCS#11 URI) must be specified for PKCS#11 certificates")
		}
		if certConfig.Certs == "" {
			return nil, fmt.Errorf("certs (PEM certificate file) must be specified for PKCS#11 certificates")
		}
		return osslsigncode.PKCS11Certificate{
			Certs:        certConfig.Certs,
			Key:          certConfig.Key,
			PKCS11Module: modulePath,
			PKCS11Engine: certConfig.PKCS11Engine,
		}, nil
	case "pkcs12":
		if certConfig.Key == "" {
			return nil, fmt.Errorf("key path must be specified for PKCS12 certificates")
		}
		return osslsigncode.PKCS12Certificate{
			PKCS12: certConfig.Key,
		}, nil
	case "file":
		if certConfig.Certs == "" {
			return nil, fmt.Errorf("certs path must be specified for file certificates")
		}
		if certConfig.Key == "" {
			return nil, fmt.Errorf("key path must be specified for file certificates")
		}
		return osslsigncode.FileCertificate{
			Certs: certConfig.Certs,
			Key:   certConfig.Key,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", certConfig.Type)
	}
}

// initializeProfiles initializes signing profiles from configuration.
func initializeProfiles(cfg *config.Config, pwProviders map[string]password.Provider) (map[string]*profiles.SignProfile, error) {
	profilesMap := make(map[string]*profiles.SignProfile)

	for name, profileConfig := range cfg.Profiles {
		profile := &profiles.SignProfile{}

		if profileConfig.Description != "" {
			profile.Description = &profileConfig.Description
		}
		if profileConfig.DescriptionURL != "" {
			profile.DescriptionURL = &profileConfig.DescriptionURL
		}

		cert, err := parseCertificate(profileConfig.Certificate, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate for profile '%s': %w", name, err)
		}
		profile.Certificate = cert

		if provName := profileConfig.Certificate.PasswordProvider; provName != "" {
			prov, ok := pwProviders[provName]
			if !ok {
				return nil, fmt.Errorf("profile '%s' references unknown password provider '%s'", name, provName)
			}
			profile.PasswordProvider = prov
		}

		profilesMap[name] = profile
	}

	return profilesMap, nil
}

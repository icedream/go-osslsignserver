package bootstrap

import (
	"fmt"
	"testing"

	"github.com/icedream/go-osslsignserver/internal/config"
	"github.com/icedream/go-osslsignserver/internal/mock/password"
	mockpkcs11 "github.com/icedream/go-osslsignserver/internal/mock/pkcs11"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPKCS11CertificateInitialization tests PKCS#11 certificate initialization.
func TestPKCS11CertificateInitialization(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantErr     bool
		errContains string
		wantType    string
	}{
		{
			name: "pkcs11 certificate with module",
			certConfig: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert.pem",
				Key:   "pkcs11:slot-id=0;object=test",
			},
			cfg:      &config.Config{PKCS11Module: "/mock/module.so"},
			wantErr:  false,
			wantType: "PKCS11Certificate",
		},
		{
			name: "pkcs11 without module",
			certConfig: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert.pem",
				Key:   "pkcs11:slot-id=0;object=test",
			},
			cfg:         &config.Config{PKCS11Module: ""},
			wantErr:     true,
			errContains: "pkcs11Module must be specified",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := parseCertificate(test.certConfig, test.cfg)

			if test.wantErr {
				require.Error(t, err)
				if test.errContains != "" {
					assert.Contains(t, err.Error(), test.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)

			if test.wantType == "PKCS11Certificate" {
				_, ok := cert.(osslsigncode.PKCS11Certificate)
				assert.True(t, ok, "Should be PKCS11Certificate")
			}
		})
	}
}

// TestPKCS12CertificateInitialization tests PKCS12 certificate initialization.
func TestPKCS12CertificateInitialization(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantErr     bool
		errContains string
		wantType    string
	}{
		{
			name: "pkcs12 certificate",
			certConfig: config.CertificateConfig{
				Type: "pkcs12",
				Key:  "/path/to/cert.p12",
			},
			cfg:      &config.Config{PKCS11Module: "/mock/module.so"},
			wantErr:  false,
			wantType: "PKCS12Certificate",
		},
		{
			name: "pkcs12 without key",
			certConfig: config.CertificateConfig{
				Type: "pkcs12",
				Key:  "",
			},
			cfg:         &config.Config{PKCS11Module: "/mock/module.so"},
			wantErr:     true,
			errContains: "key path must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificate(tt.certConfig, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)

			if tt.wantType == "PKCS12Certificate" {
				_, ok := cert.(osslsigncode.PKCS12Certificate)
				assert.True(t, ok, "Should be PKCS12Certificate")
			}
		})
	}
}

// TestFileCertificateInitialization tests file certificate initialization.
func TestFileCertificateInitialization(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantErr     bool
		errContains string
		wantType    string
	}{
		{
			name: "file certificate",
			certConfig: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "/path/to/cert.pem",
			},
			cfg:      &config.Config{PKCS11Module: ""},
			wantErr:  false,
			wantType: "FileCertificate",
		},
		{
			name: "file certificate without key",
			certConfig: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "",
			},
			cfg:         &config.Config{PKCS11Module: ""},
			wantErr:     true,
			errContains: "key path must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificate(tt.certConfig, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)

			if tt.wantType == "FileCertificate" {
				_, ok := cert.(osslsigncode.FileCertificate)
				assert.True(t, ok, "Should be FileCertificate")
			}
		})
	}
}

// TestPKCS11ProfileInitialization tests PKCS#11 profile initialization.
func TestPKCS11ProfileInitialization(t *testing.T) {
	profiles := map[string]config.SignProfile{
		"test": {
			Certificate: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert.pem",
				Key:   "pkcs11:slot-id=0;object=test",
			},
			Timestamper: config.TimestampConfig{
				Type: "authority",
				URLs: []string{"https://example.com/tsa"},
			},
			Description:    "Test PKCS11 Profile",
			DescriptionURL: "https://example.com",
		},
	}

	cfg := &config.Config{
		PKCS11Module: "/mock/module.so",
		Profiles:     profiles,
	}

	profilesMap, err := initializeProfiles(cfg, nil)

	require.NoError(t, err)
	assert.Len(t, profilesMap, 1)

	profile := profilesMap["test"]
	assert.NotNil(t, profile)
	assert.Equal(t, "Test PKCS11 Profile", *profile.Description)
}

// TestUnsupportedCertificateType tests error handling for unsupported certificate types.
func TestUnsupportedCertificateType(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantErr     bool
		errContains string
	}{
		{
			name: "unsupported certificate type",
			certConfig: config.CertificateConfig{
				Type: "unsupported",
				Key:  "/path/to/cert.pem",
			},
			cfg:         &config.Config{PKCS11Module: ""},
			wantErr:     true,
			errContains: "unsupported certificate type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCertificate(tt.certConfig, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestCertificateWithMissingKey tests error handling when certificate key is missing.
func TestCertificateWithMissingKey(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantErr     bool
		errContains string
	}{
		{
			name: "file certificate without key path",
			certConfig: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "",
			},
			cfg:         &config.Config{PKCS11Module: ""},
			wantErr:     true,
			errContains: "key path must be specified",
		},
		{
			name: "pkcs11 certificate without key specification",
			certConfig: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert.pem",
				Key:   "",
			},
			cfg:         &config.Config{PKCS11Module: "/mock/module.so"},
			wantErr:     true,
			errContains: "key (PKCS#11 URI) must be specified for PKCS#11 certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCertificate(tt.certConfig, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestMultipleProfilesInitialization tests initialization of multiple signing profiles.
func TestMultipleProfilesInitialization(t *testing.T) {
	profiles := map[string]config.SignProfile{
		"profile1": {
			Certificate: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert1.pem",
				Key:   "/path/to/cert1.pem",
			},
			Timestamper: config.TimestampConfig{
				Type: "authority",
				URLs: []string{"https://example.com/tsa1"},
			},
			Description:    "Profile 1",
			DescriptionURL: "https://example.com/1",
		},
		"profile2": {
			Certificate: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert2.pem",
				Key:   "pkcs11:slot-id=0;object=test",
			},
			Timestamper: config.TimestampConfig{
				Type: "rfc3161",
				URLs: []string{"https://example.com/tsa2"},
			},
			Description:    "Profile 2",
			DescriptionURL: "https://example.com/2",
		},
		"profile3": {
			Certificate: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert3.pem",
				Key:   "/path/to/cert3.pem",
			},
			Description:    "Profile 3",
			DescriptionURL: "https://example.com/3",
		},
	}

	cfg := &config.Config{
		PKCS11Module: "/mock/module.so",
		Profiles:     profiles,
	}

	profilesMap, err := initializeProfiles(cfg, nil)

	require.NoError(t, err)
	assert.Len(t, profilesMap, 3)

	// Verify profile1
	profile1 := profilesMap["profile1"]
	assert.NotNil(t, profile1)
	assert.NotNil(t, profile1.Certificate)
	_, ok := profile1.Certificate.(osslsigncode.FileCertificate)
	assert.True(t, ok, "Profile 1 should have FileCertificate")
	assert.Equal(t, "Profile 1", *profile1.Description)
	assert.Equal(t, "https://example.com/1", *profile1.DescriptionURL)

	// Verify profile2
	profile2 := profilesMap["profile2"]
	assert.NotNil(t, profile2)
	assert.NotNil(t, profile2.Certificate)
	_, ok = profile2.Certificate.(osslsigncode.PKCS11Certificate)
	assert.True(t, ok, "Profile 2 should have PKCS11Certificate")
	assert.Equal(t, "Profile 2", *profile2.Description)
	assert.Equal(t, "https://example.com/2", *profile2.DescriptionURL)

	// Verify profile3
	profile3 := profilesMap["profile3"]
	assert.NotNil(t, profile3)
	assert.NotNil(t, profile3.Certificate)
	_, ok = profile3.Certificate.(osslsigncode.FileCertificate)
	assert.True(t, ok, "Profile 3 should have FileCertificate")
	assert.Equal(t, "Profile 3", *profile3.Description)
	assert.Equal(t, "https://example.com/3", *profile3.DescriptionURL)
}

// TestProfileWithOnlyDescription tests profile with only description fields set.
func TestProfileWithOnlyDescription(t *testing.T) {
	profiles := map[string]config.SignProfile{
		"test": {
			Certificate: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "/path/to/cert.pem",
			},
			Description:    "Test Profile",
			DescriptionURL: "https://example.com",
		},
	}

	cfg := &config.Config{
		PKCS11Module: "/mock/module.so",
		Profiles:     profiles,
	}

	profilesMap, err := initializeProfiles(cfg, nil)

	require.NoError(t, err)
	assert.Len(t, profilesMap, 1)

	profile := profilesMap["test"]
	assert.NotNil(t, profile)
	assert.NotNil(t, profile.Description)
	assert.Equal(t, "Test Profile", *profile.Description)
	assert.NotNil(t, profile.DescriptionURL)
	assert.Equal(t, "https://example.com", *profile.DescriptionURL)
	assert.NotNil(t, profile.Certificate)
}

// TestProfileWithoutDescription tests profile with no description fields.
func TestProfileWithoutDescription(t *testing.T) {
	profiles := map[string]config.SignProfile{
		"test": {
			Certificate: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "/path/to/cert.pem",
			},
		},
	}

	cfg := &config.Config{
		PKCS11Module: "/mock/module.so",
		Profiles:     profiles,
	}

	profilesMap, err := initializeProfiles(cfg, nil)

	require.NoError(t, err)
	assert.Len(t, profilesMap, 1)

	profile := profilesMap["test"]
	assert.NotNil(t, profile)
	assert.Nil(t, profile.Description)
	assert.Nil(t, profile.DescriptionURL)
	assert.NotNil(t, profile.Certificate)
}

// TestProfileWithEmptyDescriptionURL tests profile with empty description URL.
func TestProfileWithEmptyDescriptionURL(t *testing.T) {
	profiles := map[string]config.SignProfile{
		"test": {
			Certificate: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "/path/to/cert.pem",
			},
			Description:    "Test Profile",
			DescriptionURL: "",
		},
	}

	cfg := &config.Config{
		PKCS11Module: "/mock/module.so",
		Profiles:     profiles,
	}

	profilesMap, err := initializeProfiles(cfg, nil)

	require.NoError(t, err)
	assert.Len(t, profilesMap, 1)

	profile := profilesMap["test"]
	assert.NotNil(t, profile)
	assert.NotNil(t, profile.Description)
	assert.Equal(t, "Test Profile", *profile.Description)
	assert.Nil(t, profile.DescriptionURL)
	assert.NotNil(t, profile.Certificate)
}

// TestValidatePINAgainstToken_Success tests successful PIN validation flow.
func TestValidatePINAgainstToken_Success(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.NoError(t, err)
	assert.True(t, mockModule.LoginCalled, "Login should have been called")
	assert.True(t, mockModule.LoginSucceeded, "Login should have succeeded")
	assert.Equal(t, 1, mockModule.LoginAttempts, "Should have attempted login once")
}

// TestValidatePINAgainstToken_NoSlots tests PIN validation when no slots are available.
func TestValidatePINAgainstToken_NoSlots(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = false // No token present

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PKCS#11 slots found")
}

// TestValidatePINAgainstToken_ModuleCreationFailure tests PIN validation when module creation fails.
func TestValidatePINAgainstToken_ModuleCreationFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.ReturnErrorOnInit = fmt.Errorf("failed to create PKCS#11 module")

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create PKCS#11 module")
}

// TestValidatePINAgainstToken_LoginFailure tests PIN validation when login fails.
func TestValidatePINAgainstToken_LoginFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = false

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to login to any PKCS#11 token with provided PIN")
	assert.True(t, mockModule.LoginAttempts >= 1, "Login should have been attempted at least once")
	assert.Equal(t, 2, mockModule.LoginAttempts, "Should have attempted login on both slots")
}

// TestValidatePINAgainstToken_AllSlotsFail tests PIN validation when all slots fail.
func TestValidatePINAgainstToken_AllSlotsFail(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = false

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to login to any PKCS#11 token with provided PIN")
	assert.True(t, mockModule.LoginCalled, "Login should have been called")
	assert.Equal(t, 2, mockModule.LoginAttempts, "Should have attempted login on all slots")
}

// TestValidatePINAgainstToken_ModuleInitializationFailure tests PIN validation when module initialization fails.
func TestValidatePINAgainstToken_ModuleInitializationFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.ReturnErrorOnInit = assert.AnError

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize PKCS#11")
}

// TestValidatePINAgainstToken_GetSlotsFailure tests PIN validation when GetSlotList fails.
func TestValidatePINAgainstToken_GetSlotsFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.ReturnErrorOnGetSlots = assert.AnError

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get slot list")
}

// TestValidatePINAgainstToken_GetTokenInfoFailure tests PIN validation when GetTokenInfo fails.
func TestValidatePINAgainstToken_GetTokenInfoFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.ReturnErrorOnGetSlots = assert.AnError

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get slot list")
}

// TestValidatePINAgainstToken_ProviderRequestFailure tests PIN validation when provider request fails.
func TestValidatePINAgainstToken_ProviderRequestFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true

	mockProvider := password.NewWithFailure(false, false)
	mockProvider.ReturnPasswordError = assert.AnError

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to request PIN")
}

// TestValidatePINAgainstToken_ProviderProgressFailure tests PIN validation when provider progress fails.
func TestValidatePINAgainstToken_ProviderProgressFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true

	mockProvider := password.NewWithFailure(false, true)
	mockProvider.FailSecondRequest = true

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to progress PIN")
}

// TestValidatePINAgainstToken_PinEnclaveFailure tests PIN validation when opening PIN enclave fails.
func TestValidatePINAgainstToken_PinEnclaveFailure(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true

	mockProvider := password.NewWithPassword("test123")
	mockProvider.ReturnPasswordError = assert.AnError

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to request PIN")
}

// TestValidatePINAgainstToken_MultipleSlotsSuccess tests PIN validation when first slot succeeds.
func TestValidatePINAgainstToken_MultipleSlotsSuccess(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true

	mockProvider := password.NewWithPassword("test123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.NoError(t, err)
	assert.True(t, mockModule.LoginCalled, "Login should have been called")
	assert.True(t, mockModule.LoginSucceeded, "Login should have succeeded")
	assert.Equal(t, 1, mockModule.LoginAttempts, "Should have attempted login once (first slot succeeded)")
}

// TestValidatePINAgainstToken_InvalidPin tests PIN validation with wrong password.
func TestValidatePINAgainstToken_InvalidPin(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = false // Simulate wrong password

	mockProvider := password.NewWithPassword("wrong123")

	err := validatePINAgainstTokenWithMock(
		mockProvider,
		mockModule,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to login to any PKCS#11 token with provided PIN")
	assert.True(t, mockModule.LoginAttempts >= 1, "Login should have been attempted at least once")
	assert.Equal(t, 2, mockModule.LoginAttempts, "Should have attempted login on both slots")
}

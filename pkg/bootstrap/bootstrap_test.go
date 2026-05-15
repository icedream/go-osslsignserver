package bootstrap

import (
	"testing"

	"github.com/icedream/go-osslsignserver/internal/config"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCertificate tests certificate parsing.
func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certConfig  config.CertificateConfig
		cfg         *config.Config
		wantType    string
		wantErr     bool
		errContains string
	}{
		{
			name: "file certificate",
			certConfig: config.CertificateConfig{
				Type:  "file",
				Certs: "/path/to/cert.pem",
				Key:   "/path/to/cert.pem",
			},
			cfg:      &config.Config{PKCS11Module: ""},
			wantType: "FileCertificate",
		},
		{
			name: "pkcs12 certificate",
			certConfig: config.CertificateConfig{
				Type: "pkcs12",
				Key:  "/path/to/cert.p12",
			},
			cfg:      &config.Config{PKCS11Module: ""},
			wantType: "PKCS12Certificate",
		},
		{
			name: "pkcs11 certificate",
			certConfig: config.CertificateConfig{
				Type:  "pkcs11",
				Certs: "/path/to/cert.pem",
				Key:   "pkcs11:slot-id=0;object=test",
			},
			cfg:      &config.Config{PKCS11Module: "/path/to/pkcs11.so"},
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
		{
			name: "unsupported type",
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
			cert, err := parseCertificate(tt.certConfig, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)

			switch tt.wantType {
			case "FileCertificate":
				_, ok := cert.(osslsigncode.FileCertificate)
				require.True(t, ok)
			case "PKCS12Certificate":
				_, ok := cert.(osslsigncode.PKCS12Certificate)
				require.True(t, ok)
			case "PKCS11Certificate":
				_, ok := cert.(osslsigncode.PKCS11Certificate)
				require.True(t, ok)
			}
		})
	}
}

// TestInitializeProfiles tests profile initialization.
func TestInitializeProfiles(t *testing.T) {
	tests := []struct {
		name        string
		profiles    map[string]config.SignProfile
		wantErr     bool
		errContains string
	}{
		{
			name: "file_certificate_profile",
			profiles: map[string]config.SignProfile{
				"test": {
					Certificate: config.CertificateConfig{
						Type:  "file",
						Certs: "/path/to/cert.pem",
						Key:   "/path/to/key.pem",
					},
					Timestamper: config.TimestampConfig{
						Type: "authority",
						URLs: []string{"https://example.com/tsa"},
					},
					Description:    "Test Profile",
					DescriptionURL: "https://example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "pkcs11_certificate_profile",
			profiles: map[string]config.SignProfile{
				"test": {
					Certificate: config.CertificateConfig{
						Type:  "pkcs11",
						Certs: "/path/to/cert.pem",
						Key:   "pkcs11:slot-id=0;object=test",
					},
					Timestamper: config.TimestampConfig{
						Type: "rfc3161",
						URLs: []string{"https://example.com/tsa"},
					},
					Description:    "Test PKCS11 Profile",
					DescriptionURL: "https://example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "profile_without_timestamper",
			profiles: map[string]config.SignProfile{
				"test": {
					Certificate: config.CertificateConfig{
						Type:  "file",
						Certs: "/path/to/cert.pem",
						Key:   "/path/to/key.pem",
					},
					Description:    "Test",
					DescriptionURL: "https://example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported_certificate_type",
			profiles: map[string]config.SignProfile{
				"test": {
					Certificate: config.CertificateConfig{
						Type: "unsupported",
						Key:  "/path/to/cert.pem",
					},
					Description:    "Test",
					DescriptionURL: "https://example.com",
				},
			},
			wantErr:     true,
			errContains: "unsupported certificate type",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				PKCS11Module: "/path/to/pkcs11.so",
				Profiles:     test.profiles,
			}

			profilesMap, err := initializeProfiles(cfg, nil)

			if test.wantErr {
				require.Error(t, err)
				if test.errContains != "" {
					require.Contains(t, err.Error(), test.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.Len(t, profilesMap, 1)

			profile := profilesMap["test"]
			require.NotNil(t, profile)
			require.NotNil(t, profile.Certificate)

			switch test.name {
			case "file_certificate_profile":
				_, ok := profile.Certificate.(osslsigncode.FileCertificate)
				assert.True(t, ok, "Should be FileCertificate")
				if profile.Description != nil {
					assert.Equal(t, "Test Profile", *profile.Description)
				}
				if profile.DescriptionURL != nil {
					assert.Equal(t, "https://example.com", *profile.DescriptionURL)
				}
			case "pkcs11_certificate_profile":
				_, ok := profile.Certificate.(osslsigncode.PKCS11Certificate)
				assert.True(t, ok, "Should be PKCS11Certificate")
				if profile.Description != nil {
					assert.Equal(t, "Test PKCS11 Profile", *profile.Description)
				}
				if profile.DescriptionURL != nil {
					assert.Equal(t, "https://example.com", *profile.DescriptionURL)
				}
			case "profile_without_timestamper":
				_, ok := profile.Certificate.(osslsigncode.FileCertificate)
				assert.True(t, ok, "Should be FileCertificate")
				if profile.Description != nil {
					assert.Equal(t, "Test", *profile.Description)
				}
				if profile.DescriptionURL != nil {
					assert.Equal(t, "https://example.com", *profile.DescriptionURL)
				}
			}
		})
	}
}

package profiles

import (
	"github.com/awnumar/memguard"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/icedream/go-osslsignserver/internal/password"
)

type SignProfile struct {
	Certificate        osslsigncode.Certificate
	CrossCertFile      string
	PINEnclave         *memguard.Enclave
	PasswordProvider   password.Provider
	AskPass            bool
	Commercial         *bool
	Description        *string
	DescriptionURL     *string
	GeneratePageHashes *bool
	HashAlgorithm      *osslsigncode.HashAlgorithm
	Timestamper        osslsigncode.Timestamper
}

func (p *SignProfile) BuildSignOptions() osslsigncode.SignOptions {
	opts := osslsigncode.SignOptions{
		Certificate:      p.Certificate,
		CrossCertFile:    p.CrossCertFile,
		PasswordProvider: p.PasswordProvider,
		AskPass:          p.AskPass,
	}

	if p.Commercial != nil {
		opts.Commercial = *p.Commercial
	}
	if p.Description != nil {
		opts.Description = *p.Description
	}
	if p.DescriptionURL != nil {
		opts.DescriptionURL = *p.DescriptionURL
	}
	if p.GeneratePageHashes != nil {
		opts.GeneratePageHashes = *p.GeneratePageHashes
	}
	if p.HashAlgorithm != nil {
		opts.HashAlgorithm = *p.HashAlgorithm
	}
	if p.Timestamper != nil {
		opts.Timestamper = p.Timestamper
	}

	// Password is handled by PasswordProvider or PINEnclave
	// PINEnclave is used when password provider is prompt
	// PasswordProvider is used when password is static

	return opts
}

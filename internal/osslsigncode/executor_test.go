package osslsigncode_test

//go:generate go run $GOROOT/src/crypto/tls/generate_cert.go --host localhost
//go:generate go run ./gen_testapp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/stretchr/testify/require"
)

func TestExecutor(t *testing.T) {
	e := osslsigncode.New()

	// must not panic on empty sign options, instead return error from command
	// reporting missing args
	result, err := e.Sign(context.Background(), osslsigncode.SignOptions{}, nil)
	osslsigncodeErr := &osslsigncode.Error{}
	require.ErrorAs(t, err, &osslsigncodeErr)
	// our best hint that osslsigncode ran into missing arguments
	require.True(t, strings.HasPrefix(osslsigncodeErr.Stdout, "\nUsage: osslsigncode"))
	require.Empty(t, result)

	// avoid osslsigncode failing due to pre-existing file
	_ = os.Remove("testapp-signed.exe")
	// remove after running osslsigncode as no longer needed by then
	defer func() { _ = os.Remove("testapp-signed.exe") }()
	// do a successful run with fake cert files
	result, err = e.Sign(context.Background(), osslsigncode.SignOptions{
		Certificate: osslsigncode.FileCertificate{
			Certs: "cert.pem",
			Key:   "key.pem",
		},
		SigningTime: time.Date(2021, time.October, 12, 18, 0, 0, 0, time.UTC),
		InputFile:   "testapp.exe",
		OutputFile:  "testapp-signed.exe",
	}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, result)
}

package osslsigncode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignOptions(t *testing.T) {
	// Must include -in and -out always
	o := &SignOptions{}
	a := o.Args()
	params := a.Get("in")
	require.NotEmpty(t, params)
	require.Len(t, params, 1)

	params = a.Get("out")
	require.NotEmpty(t, params)
	require.Len(t, params, 1)

	// Test with file certificate
	o.Certificate = FileCertificate{
		Certs: "/path/to/cert.pem",
		Key:   "/path/to/key.pem",
	}
	a = o.Args()
	params = a.Get("in")
	require.NotEmpty(t, params)
	require.Len(t, params, 1)

	params = a.Get("certs")
	require.NotEmpty(t, params)
	require.Len(t, params, 1)

	params = a.Get("key")
	require.NotEmpty(t, params)
	require.Len(t, params, 1)
}

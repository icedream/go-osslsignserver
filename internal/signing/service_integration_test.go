package signing

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/icedream/go-osslsignserver/internal/config"
	mockpkcs11 "github.com/icedream/go-osslsignserver/internal/mock/pkcs11"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/icedream/go-osslsignserver/internal/password"
	"github.com/icedream/go-osslsignserver/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── mock helpers ────────────────────────────────────────────────────────────

// mockPasswordProvider is a simple mock of password.Provider for testing.
type mockPasswordProvider struct {
	password string
}

func (m *mockPasswordProvider) RequestPassword(_ password.Request) (password.Token, error) {
	return password.RandomToken(), nil
}

func (m *mockPasswordProvider) Progress(_ password.Token) (password.Report, error) {
	enc := memguard.NewEnclave([]byte(m.password))
	if enc == nil {
		return password.Report{}, fmt.Errorf("failed to create password enclave")
	}
	return password.Report{
		Status:   password.Approved,
		Password: enc,
	}, nil
}

// mockExecutor satisfies osslsigncode.ExecutorIface without invoking osslsigncode.
type mockExecutor struct {
	// returnData is written to the OutputFile on success.
	returnData []byte
	// returnErr, if non-nil, is returned instead.
	returnErr error
	// block, if true, blocks until the context is cancelled.
	block bool
	// lastOpts captures the most recent signing options.
	lastOpts osslsigncode.SignOptions
}

func (m *mockExecutor) Sign(ctx context.Context, opts osslsigncode.SignOptions, _ []*os.File) (osslsigncode.Result, error) {
	m.lastOpts = opts
	if m.block {
		<-ctx.Done()
		return osslsigncode.Result{}, ctx.Err()
	}
	if m.returnErr != nil {
		return osslsigncode.Result{}, m.returnErr
	}
	data := m.returnData
	if data == nil {
		data = []byte("signed-output")
	}
	if err := os.WriteFile(opts.OutputFile, data, 0600); err != nil {
		return osslsigncode.Result{}, err
	}
	return osslsigncode.Result{}, nil
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestSign_Success tests successful signing with a mock executor and file certificate.
func TestSign_Success(t *testing.T) {
	testData := []byte("test file content")

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.FileCertificate{
				Certs: "/fake/cert.pem",
				Key:   "/fake/key.pem",
			},
			PasswordProvider: &mockPasswordProvider{password: "testpassword123"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result)
}

// TestSign_PKCS11_Success tests successful signing with a mock PKCS#11 module and mock executor.
func TestSign_PKCS11_Success(t *testing.T) {
	mockModule := mockpkcs11.New()
	mockModule.SimulateTokenPresence = true
	mockModule.SimulateLoginSuccess = true
	mockModule.SimulateSignSuccess = true

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.PKCS11Certificate{
				Certs:        "pkcs11:slot-id=0;object=test",
				Key:          "pkcs11:slot-id=0;object=test",
				PKCS11Module: mockModule.ModulePath(),
			},
			PasswordProvider: &mockPasswordProvider{password: "testpassword123"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test file content")
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result)
}

// TestSign_ConcurrentLimitReached tests that concurrent requests are limited.
func TestSign_ConcurrentLimitReached(t *testing.T) {
	// Use a blocking executor so the first request occupies the semaphore slot.
	exec := &mockExecutor{block: true}

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, exec, profs)
	testData := []byte("test content")

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	// Start a long-running sign in the background to fill the slot.
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.Sign(ctx1, "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil) //nolint:errcheck
	}()

	// Give the goroutine time to acquire the semaphore.
	time.Sleep(50 * time.Millisecond)

	// Second call must be rejected immediately.
	result2, err2 := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)
	assert.ErrorIs(t, err2, ErrConcurrentLimitReached)
	assert.Nil(t, result2)

	cancel1()
	<-done
}

// TestSign_ProfileNotFound tests error handling when profile is not found.
func TestSign_ProfileNotFound(t *testing.T) {
	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test content")
	result, err := service.Sign(context.Background(), "nonexistent", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	assert.ErrorIs(t, err, ErrProfileNotFound)
	assert.Nil(t, result)
}

// TestSign_TokenUnavailable tests error handling when no password provider is set.
func TestSign_TokenUnavailable(t *testing.T) {
	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.PKCS11Certificate{Certs: "/fake/cert.pem", Key: "pkcs11:slot-id=0;object=test", PKCS11Module: "/fake/module.so"},
			// No PasswordProvider, no AskPass → ErrTokenUnavailable
		},
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test content")
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	assert.ErrorIs(t, err, ErrTokenUnavailable)
	assert.Nil(t, result)
}

// TestSign_Timeout tests error handling when signing times out.
func TestSign_Timeout(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{block: true}, profs)
	testData := []byte("test content")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, err := service.Sign(ctx, "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	assert.ErrorIs(t, err, ErrSigningTimeout)
	assert.Nil(t, result)
}

// TestSign_WorkDirCleanup tests that work directories are cleaned up after signing.
func TestSign_WorkDirCleanup(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	workDir := t.TempDir()
	cfg := &config.Config{
		WorkDir:               workDir,
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test content")
	_, _ = service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	time.Sleep(50 * time.Millisecond)
	entries, err := os.ReadDir(workDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "job dirs should have been cleaned up")
}

// TestSign_EmptyArtifact tests signing with an empty artifact.
func TestSign_EmptyArtifact(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	// Executor returns an error, simulating osslsigncode rejecting empty input.
	service := NewService(cfg, &mockExecutor{returnErr: fmt.Errorf("empty artifact")}, profs)
	result, err := service.Sign(context.Background(), "test", bytes.NewReader([]byte{}), 0, nil, nil, nil)

	assert.ErrorIs(t, err, ErrSigningFailed)
	assert.Nil(t, result)
}

// TestSign_SmallArtifact tests signing with a very small artifact.
func TestSign_SmallArtifact(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{returnErr: fmt.Errorf("too small")}, profs)
	result, err := service.Sign(context.Background(), "test", bytes.NewReader([]byte("x")), 1, nil, nil, nil)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestSign_MultipleProfiles tests that each profile is addressed independently.
func TestSign_MultipleProfiles(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"profile1": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert1.pem", Key: "/fake/key1.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin1"},
		},
		"profile2": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert2.pem", Key: "/fake/key2.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin2"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 2,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test file content")

	for _, id := range []string{"profile1", "profile2"} {
		result, err := service.Sign(context.Background(), id, bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)
		assert.NoError(t, err, "profile %s", id)
		assert.NotNil(t, result, "profile %s", id)
	}
}

// TestSign_FileCertificate tests signing with a file certificate (success path).
func TestSign_FileCertificate(t *testing.T) {
	testData := []byte("test file content")

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pass"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestSign_PKCS11Certificate tests signing with a PKCS#11 certificate via mock executor.
func TestSign_PKCS11Certificate(t *testing.T) {
	mockModule := mockpkcs11.New()

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.PKCS11Certificate{
				Certs:        "pkcs11:slot-id=0;object=test",
				Key:          "pkcs11:slot-id=0;object=test",
				PKCS11Module: mockModule.ModulePath(),
			},
			PasswordProvider: &mockPasswordProvider{password: "testpassword123"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test file content")
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result)
}

// TestSign_WorkDirCreation tests that the work directory is created if it does not exist.
func TestSign_WorkDirCreation(t *testing.T) {
	workDir := t.TempDir()
	subDir := workDir + "/jobs"

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               subDir,
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test file content")
	_, _ = service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	_, err := os.Stat(subDir)
	assert.NoError(t, err)
}

// TestSign_WithPasswordProvider tests signing when AskPass is true (interactive fallback path).
// We use a blocking context-cancel to simulate the interactive flow failing without
// actually blocking stdin.
func TestSign_WithPasswordProvider(t *testing.T) {
	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.PKCS11Certificate{
				Certs:        "pkcs11:slot-id=0;object=test",
				Key:          "pkcs11:slot-id=0;object=test",
				PKCS11Module: "/path/to/module.so",
			},
			// No PasswordProvider; AskPass requires a real terminal — just verify
			// it routes through the AskPass branch and fails gracefully.
			AskPass: true,
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	exec := &mockExecutor{}
	service := NewService(cfg, exec, profs)
	testData := []byte("test file content")
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, exec.lastOpts.AskPass)
}

// TestSign_HashAndDescription tests that hash/description parameters are accepted.
func TestSign_HashAndDescription(t *testing.T) {
	testData := []byte("test file content")

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)

	hash := "abc123"
	description := "Test description"
	descriptionURL := "https://example.com/description"

	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), &hash, &description, &descriptionURL)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestSign_ProfileLock tests that profile locks prevent concurrent access to the same profile.
func TestSign_ProfileLock(t *testing.T) {
	// With MaxConcurrentRequests=1 only one request can be in-flight.
	exec := &mockExecutor{block: true}

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, exec, profs)
	testData := []byte("test content")

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	done := make(chan struct{})
	go func() {
		defer close(done)
		service.Sign(ctx1, "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil) //nolint:errcheck
	}()

	time.Sleep(50 * time.Millisecond)

	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)
			results <- err
		}()
	}

	for i := 0; i < 2; i++ {
		err := <-results
		assert.ErrorIs(t, err, ErrConcurrentLimitReached)
	}

	cancel1()
	<-done
}

// TestSign_RFC3161Timestamper tests signing with RFC3161 timestamper via mock executor.
func TestSign_RFC3161Timestamper(t *testing.T) {
	mockModule := mockpkcs11.New()

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate: osslsigncode.PKCS11Certificate{
				Certs:        "pkcs11:slot-id=0;object=test",
				Key:          "pkcs11:slot-id=0;object=test",
				PKCS11Module: mockModule.ModulePath(),
			},
			PasswordProvider: &mockPasswordProvider{password: "testpassword123"},
			Timestamper: osslsigncode.RFC3161AuthorityServerTimestamper{
				URLs: []string{"https://timestamp.example.com"},
			},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, &mockExecutor{}, profs)
	testData := []byte("test file content")
	result, err := service.Sign(context.Background(), "test", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result)
}

// TestSign_ConcurrentDifferentProfiles tests concurrent operations on different profiles
// are serialised by the global semaphore when MaxConcurrentRequests=1.
func TestSign_ConcurrentDifferentProfiles(t *testing.T) {
	exec := &mockExecutor{block: true}

	profs := map[string]*profiles.SignProfile{
		"test1": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
		"test2": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert2.pem", Key: "/fake/key2.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	service := NewService(cfg, exec, profs)
	testData := []byte("test content")

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	done := make(chan struct{})
	go func() {
		defer close(done)
		service.Sign(ctx1, "test1", bytes.NewReader(testData), int64(len(testData)), nil, nil, nil) //nolint:errcheck
	}()

	time.Sleep(50 * time.Millisecond)

	results := make(chan error, 4)
	for i := 1; i <= 2; i++ {
		for j := 0; j < 2; j++ {
			id := fmt.Sprintf("test%d", i)
			go func(profileID string) {
				_, err := service.Sign(context.Background(), profileID, bytes.NewReader(testData), int64(len(testData)), nil, nil, nil)
				results <- err
			}(id)
		}
	}

	for i := 0; i < 4; i++ {
		err := <-results
		assert.ErrorIs(t, err, ErrConcurrentLimitReached)
	}

	cancel1()
	<-done
}

// TestSign_DescriptionOverride tests that passed-in description and description_url
// override the profile defaults in the signing options.
func TestSign_DescriptionOverride(t *testing.T) {
	testData := []byte("test file content")

	// Create a profile with default description
	profileDesc := "Profile default description"
	profileDescURL := "https://profile.example.com"

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
			Description:      &profileDesc,
			DescriptionURL:   &profileDescURL,
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	exec := &mockExecutor{}
	service := NewService(cfg, exec, profs)

	// Pass different description values in the request
	requestDesc := "Request override description"
	requestDescURL := "https://request.example.com"

	result, err := service.Sign(
		context.Background(),
		"test",
		bytes.NewReader(testData),
		int64(len(testData)),
		nil,
		&requestDesc,
		&requestDescURL,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the request values overrode the profile defaults
	assert.Equal(t, requestDesc, exec.lastOpts.Description, "description should be overridden")
	assert.Equal(t, requestDescURL, exec.lastOpts.DescriptionURL, "description_url should be overridden")
}

// TestSign_DescriptionProfileDefault tests that profile defaults are used
// when no description is passed in the request.
func TestSign_DescriptionProfileDefault(t *testing.T) {
	testData := []byte("test file content")

	// Create a profile with default description
	profileDesc := "Profile default description"
	profileDescURL := "https://profile.example.com"

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
			Description:      &profileDesc,
			DescriptionURL:   &profileDescURL,
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	exec := &mockExecutor{}
	service := NewService(cfg, exec, profs)

	// Don't pass description values in the request
	result, err := service.Sign(
		context.Background(),
		"test",
		bytes.NewReader(testData),
		int64(len(testData)),
		nil,
		nil,
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the profile defaults are used
	assert.Equal(t, profileDesc, exec.lastOpts.Description, "profile default description should be used")
	assert.Equal(t, profileDescURL, exec.lastOpts.DescriptionURL, "profile default description_url should be used")
}

// TestSign_PartialDescriptionOverride tests that we can override just description
// or just description_url while preserving profile defaults for the other field.
func TestSign_PartialDescriptionOverride(t *testing.T) {
	testData := []byte("test file content")

	profileDesc := "Profile description"
	profileDescURL := "https://profile.example.com"

	profs := map[string]*profiles.SignProfile{
		"test": {
			Certificate:      osslsigncode.FileCertificate{Certs: "/fake/cert.pem", Key: "/fake/key.pem"},
			PasswordProvider: &mockPasswordProvider{password: "pin"},
			Description:      &profileDesc,
			DescriptionURL:   &profileDescURL,
		},
	}

	cfg := &config.Config{
		WorkDir:               t.TempDir(),
		MaxConcurrentRequests: 1,
	}

	exec := &mockExecutor{}
	service := NewService(cfg, exec, profs)

	// Override only description, not description_url
	requestDesc := "Request override description"

	result, err := service.Sign(
		context.Background(),
		"test",
		bytes.NewReader(testData),
		int64(len(testData)),
		nil,
		&requestDesc,
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify description was overridden but description_url remains default
	assert.Equal(t, requestDesc, exec.lastOpts.Description, "description should be overridden")
	assert.Equal(t, profileDescURL, exec.lastOpts.DescriptionURL, "description_url should remain profile default")
}

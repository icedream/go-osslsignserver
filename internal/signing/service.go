package signing

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/icedream/go-osslsignserver/internal/config"
	"github.com/icedream/go-osslsignserver/internal/osslsigncode"
	"github.com/icedream/go-osslsignserver/internal/password"
	"github.com/icedream/go-osslsignserver/internal/profiles"
)

type Service struct {
	cfg          *config.Config
	executor     osslsigncode.ExecutorIface
	profiles     map[string]*profiles.SignProfile
	workDir      string
	semaphore    chan struct{}
	profileMu    sync.Mutex
	profileLocks map[string]*sync.Mutex
	logger       *slog.Logger
}

func NewService(cfg *config.Config, executor osslsigncode.ExecutorIface, profiles map[string]*profiles.SignProfile) *Service {
	return &Service{
		cfg:          cfg,
		executor:     executor,
		profiles:     profiles,
		workDir:      cfg.WorkDir,
		semaphore:    make(chan struct{}, cfg.MaxConcurrentRequests),
		profileLocks: make(map[string]*sync.Mutex),
		logger:       slog.Default(),
	}
}

// Sign performs the signing operation for a given profile.
func (s *Service) Sign(ctx context.Context, profileID string, artifactReader io.Reader, artifactSize int64, hash *string, description *string, descriptionURL *string) ([]byte, error) {
	// Handle optional hash, description, and descriptionURL parameters
	_ = hash
	_ = description
	_ = descriptionURL
	_ = artifactSize // Placeholder for future use

	profile, ok := s.profiles[profileID]
	if !ok {
		return nil, ErrProfileNotFound
	}

	// 1. Global semaphore for concurrency control
	select {
	case s.semaphore <- struct{}{}:
	default:
		// Semaphore is full - return error
		return nil, ErrConcurrentLimitReached
	}
	defer func() { <-s.semaphore }()

	// 2. Acquire profile-specific lock
	profileMu, ok := s.profileLocks[profileID]
	if !ok {
		profileMu = &sync.Mutex{}
		s.profileMu.Lock()
		s.profileLocks[profileID] = profileMu
		s.profileMu.Unlock()
	}
	profileMu.Lock()
	defer profileMu.Unlock()

	// 3. Check token availability
	// File-based certificates don't require a password provider
	s.logger.Debug("sign request",
		"certificateType", profile.Certificate.CertificateType(),
		"hasPasswordProvider", profile.PasswordProvider != nil,
		"askPass", profile.AskPass,
	)
	if profile.Certificate.CertificateType() != "file" && profile.PasswordProvider == nil && !profile.AskPass {
		return nil, ErrTokenUnavailable
	}

	// 4. Create job directory
	jobID := uuid.New().String()
	jobDir := filepath.Join(s.workDir, jobID)
	if err := os.MkdirAll(jobDir, 0700); err != nil {
		return nil, ErrSigningFailed
	}
	defer func() { _ = os.RemoveAll(jobDir) }()

	// 5. Stream artifact to disk
	inputPath := filepath.Join(jobDir, "input")
	f, err := os.Create(inputPath)
	if err != nil {
		return nil, ErrSigningFailed
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, artifactReader); err != nil {
		return nil, ErrSigningFailed
	}

	// 6. Prepare signing options
	opts := profile.BuildSignOptions()
	opts.InputFile = inputPath
	outputPath := filepath.Join(jobDir, "output")
	opts.OutputFile = outputPath

	// 7. Get password from provider
	var extraFiles []*os.File

	if profile.PasswordProvider != nil {
		desc := ""
		if profile.Description != nil {
			desc = *profile.Description
		}
		token, err := profile.PasswordProvider.RequestPassword(password.Request{Description: desc})
		if err != nil {
			return nil, ErrSigningFailed
		}
		report, err := profile.PasswordProvider.Progress(token)
		if err != nil {
			return nil, ErrSigningFailed
		}
		if report.Status != password.Approved || report.Password == nil {
			return nil, ErrSigningFailed
		}
		passwordBuf, err := report.Password.Open()
		if err != nil || passwordBuf == nil {
			return nil, ErrSigningFailed
		}
		defer passwordBuf.Destroy()

		// Deliver PIN via pipe on fd 3 so osslsigncode never tries to open a terminal.
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, ErrSigningFailed
		}
		defer func() { _ = pr.Close() }()
		go func() {
			_, _ = pw.Write(passwordBuf.Bytes())
			_ = pw.Close()
		}()
		opts.ReadPass = "/dev/fd/3"
		extraFiles = []*os.File{pr}
	}

	// 8. Execute command with timeout
	type result struct {
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		_, err := s.executor.Sign(ctx, opts, extraFiles)
		resultCh <- result{err: err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			// If the context was also cancelled, prefer the timeout error.
			if ctx.Err() != nil {
				_ = os.RemoveAll(jobDir)
				return nil, ErrSigningTimeout
			}
			return nil, ErrSigningFailed
		}
		// Check output file
		if _, err := os.Stat(outputPath); err != nil {
			return nil, ErrSigningFailed
		}
		outputData, err := os.ReadFile(outputPath)
		if err != nil {
			return nil, ErrSigningFailed
		}
		return outputData, nil
	case <-ctx.Done():
		// Timeout occurred - cleanup and return error
		_ = os.RemoveAll(jobDir)
		return nil, ErrSigningTimeout
	}
}

// Error constants
var (
	ErrProfileNotFound        = fmt.Errorf("profile not found")
	ErrConcurrentLimitReached = fmt.Errorf("concurrent request limit reached")
	ErrTokenUnavailable       = fmt.Errorf("token unavailable")
	ErrSigningTimeout         = fmt.Errorf("signing timeout")
	ErrSigningFailed          = fmt.Errorf("signing failed")
)

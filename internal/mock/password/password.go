package password

import (
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/icedream/go-osslsignserver/internal/password"
)

// MockProvider is a mock implementation of password.Provider for testing.
type MockProvider struct {
	// Configuration
	ReturnPassword      string
	ReturnPasswordError error
	FailFirstRequest    bool
	FailSecondRequest   bool
	TrackRequests       bool

	// State tracking
	requests []password.Request
	// reportCount tracks how many Progress() calls were made
	reportCount int
	// passwordEnclave is stored to prevent cleanup until test completion
	passwordEnclave *memguard.Enclave
	// GetReportCountFunc returns the number of Progress calls
	GetReportCountFunc func() int
}

// RequestPassword mocks password.Provider.RequestPassword().
func (m *MockProvider) RequestPassword(req password.Request) (password.Token, error) {
	if m.TrackRequests {
		m.requests = append(m.requests, req)
	}

	if m.FailFirstRequest && len(m.requests) == 1 {
		return nil, m.ReturnPasswordError
	}

	if m.ReturnPasswordError != nil {
		return nil, m.ReturnPasswordError
	}

	return password.RandomToken(), nil
}

// Progress mocks password.Provider.Progress().
func (m *MockProvider) Progress(token password.Token) (password.Report, error) {
	m.reportCount++

	if m.FailSecondRequest && m.reportCount == 2 {
		return password.Report{
			Status:   password.Failed,
			Password: nil,
		}, errors.New("progress failed")
	}

	if m.ReturnPasswordError != nil {
		return password.Report{}, m.ReturnPasswordError
	}

	// Create password enclave with the test password
	enclosure := memguard.NewEnclave([]byte(m.ReturnPassword))
	if enclosure == nil {
		return password.Report{}, fmt.Errorf("failed to create password enclave")
	}

	m.passwordEnclave = enclosure

	return password.Report{
		Status:   password.Approved,
		Password: enclosure,
	}, nil
}

// GetReportCount returns the number of Progress calls made.
func (m *MockProvider) GetReportCount() int {
	if m.GetReportCountFunc != nil {
		return m.GetReportCountFunc()
	}
	return m.reportCount
}

// NewWithPassword creates a mock provider with a specific password.
func NewWithPassword(password string) *MockProvider {
	return &MockProvider{
		ReturnPassword: password,
	}
}

// NewWithFailure creates a mock provider that fails on first or second request.
func NewWithFailure(failFirst, failSecond bool) *MockProvider {
	return &MockProvider{
		FailFirstRequest:  failFirst,
		FailSecondRequest: failSecond,
	}
}

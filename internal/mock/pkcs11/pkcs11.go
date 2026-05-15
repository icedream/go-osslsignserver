package pkcs11

import (
	"fmt"
)

// MockPKCS11 is a mock implementation of the pkcs11 library interface.
// It simulates PKCS#11 token operations for testing purposes.
type MockPKCS11 struct {
	// Configuration
	SimulateTokenPresence bool
	SimulateLoginSuccess  bool
	SimulateSignSuccess   bool
	ReturnErrorOnInit     error
	ReturnErrorOnGetSlots error
	ReturnErrorOnLogin    error

	// State tracking
	Initialized    bool
	loginAttempts  int
	loginSucceeded bool
	openSessions   map[uint]bool
	// Exported fields for testing
	LoginCalled    bool
	LoginSucceeded bool
	LoginAttempts  int
}

// Slot represents a PKCS#11 slot.
type Slot struct {
	ID        uint
	Token     bool
	Removable bool
}

// Session represents a PKCS#11 session.
type Session struct {
	ID     uint
	SlotID uint
	Opened bool
}

// TokenInfo represents PKCS#11 token information.
type TokenInfo struct {
	Label        string
	SerialNumber string
	Model        string
	Manufacturer string
}

// Initialize mocks pkcs11.Initialize().
func (m *MockPKCS11) Initialize() error {
	if m.ReturnErrorOnInit != nil {
		return m.ReturnErrorOnInit
	}
	m.Initialized = true
	return nil
}

// Finalize mocks pkcs11.Finalize().
func (m *MockPKCS11) Finalize() error {
	m.Initialized = false
	return nil
}

// Destroy mocks pkcs11.Destroy().
func (m *MockPKCS11) Destroy() {
	m.Initialized = false
	m.openSessions = make(map[uint]bool)
	m.LoginCalled = false
	m.LoginSucceeded = false
	m.LoginAttempts = 0
}

// GetSlotList mocks pkcs11.GetSlotList().
func (m *MockPKCS11) GetSlotList(tokenPresent bool) ([]Slot, error) {
	if !m.Initialized {
		return nil, nil
	}

	if m.ReturnErrorOnGetSlots != nil {
		return nil, m.ReturnErrorOnGetSlots
	}

	if !m.SimulateTokenPresence {
		return []Slot{}, nil
	}

	return []Slot{
		{
			ID:        0,
			Token:     true,
			Removable: true,
		},
		{
			ID:        1,
			Token:     true,
			Removable: true,
		},
	}, nil
}

// OpenSession mocks pkcs11.OpenSession().
func (m *MockPKCS11) OpenSession(slotID uint, flags uint) (Session, error) {
	if !m.Initialized {
		return Session{}, nil
	}

	if !m.SimulateTokenPresence {
		return Session{}, nil
	}

	session := Session{
		ID:     uint(len(m.openSessions)),
		SlotID: slotID,
		Opened: true,
	}

	m.openSessions[slotID] = true
	return session, nil
}

// CloseSession mocks pkcs11.CloseSession().
func (m *MockPKCS11) CloseSession(session Session) error {
	if !m.Initialized {
		return nil
	}

	delete(m.openSessions, session.SlotID)
	return nil
}

// GetTokenInfo mocks pkcs11.GetTokenInfo().
func (m *MockPKCS11) GetTokenInfo(slotID uint) (TokenInfo, error) {
	if !m.Initialized {
		return TokenInfo{}, fmt.Errorf("PKCS#11 not initialized")
	}

	if !m.SimulateTokenPresence {
		return TokenInfo{}, fmt.Errorf("token not present")
	}

	if m.ReturnErrorOnGetSlots != nil {
		return TokenInfo{}, m.ReturnErrorOnGetSlots
	}

	return TokenInfo{
		Label:        "Test Token",
		SerialNumber: "TEST123456",
		Model:        "Test Token Model",
		Manufacturer: "Test Manufacturer",
	}, nil
}

// Login mocks pkcs11.Login().
func (m *MockPKCS11) Login(session Session, userType uint, pin string) error {
	// Track that login was attempted
	m.loginAttempts++
	m.LoginAttempts = m.loginAttempts
	m.LoginCalled = true

	if !m.Initialized {
		return fmt.Errorf("PKCS#11 not initialized")
	}

	if !m.SimulateLoginSuccess {
		return fmt.Errorf("login failed")
	}

	if m.ReturnErrorOnLogin != nil {
		return m.ReturnErrorOnLogin
	}

	m.loginSucceeded = true
	// Sync exported fields
	m.LoginSucceeded = true
	return nil
}

// LoginWithTracking is a helper for testing that tracks even failed login attempts.
func (m *MockPKCS11) LoginWithTracking(session Session, userType uint, pin string) error {
	return m.LoginForTesting(session, userType, pin)
}

// LoginForTesting is a helper for testing that doesn't track login attempts.
func (m *MockPKCS11) LoginForTesting(session Session, userType uint, pin string) error {
	if !m.Initialized {
		return fmt.Errorf("PKCS#11 not initialized")
	}

	// Track that login was attempted
	m.loginAttempts++
	m.LoginAttempts = m.loginAttempts
	m.LoginCalled = true

	if !m.SimulateLoginSuccess {
		return fmt.Errorf("login failed")
	}

	if m.ReturnErrorOnLogin != nil {
		return m.ReturnErrorOnLogin
	}

	m.loginSucceeded = true
	// Sync exported fields
	m.LoginSucceeded = true
	return nil
}

// LoginForTestingWithTracking is a helper for testing that tracks failed login attempts.
func (m *MockPKCS11) LoginForTestingWithTracking(session Session, userType uint, pin string) error {
	if !m.Initialized {
		return fmt.Errorf("PKCS#11 not initialized")
	}

	if !m.SimulateLoginSuccess {
		return fmt.Errorf("login failed")
	}

	if m.ReturnErrorOnLogin != nil {
		return m.ReturnErrorOnLogin
	}

	m.loginSucceeded = true
	// Sync exported fields
	m.LoginCalled = true
	m.LoginSucceeded = true
	return nil
}

// Logout mocks pkcs11.Logout().
func (m *MockPKCS11) Logout(session Session) error {
	m.loginSucceeded = false
	return nil
}

// Sign mocks pkcs11.Sign().
func (m *MockPKCS11) Sign(session Session, data []byte) ([]byte, error) {
	if !m.Initialized || !m.SimulateSignSuccess {
		return nil, nil
	}

	// Return a simple signature (empty for mock)
	return []byte{}, nil
}

// New creates a new MockPKCS11 instance with default configuration.
func New() *MockPKCS11 {
	return &MockPKCS11{
		SimulateTokenPresence: true,
		SimulateLoginSuccess:  true,
		SimulateSignSuccess:   true,
		openSessions:          make(map[uint]bool),
		LoginCalled:           false,
		LoginSucceeded:        false,
		LoginAttempts:         0,
	}
}

// ModulePath returns the path to the mock PKCS#11 module (simulated).
func (m *MockPKCS11) ModulePath() string {
	// For testing purposes, return a dummy path
	return "/mock/pkcs11/module.so"
}

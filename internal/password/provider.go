package password

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/awnumar/memguard"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	ErrBadToken         = errors.New("bad token")
	ErrProviderNotFound = errors.New("provider not found")
)

type Status byte

const (
	Waiting Status = iota
	Approved
	Rejected
	Failed
)

type Request struct {
	Description string
}

type Report struct {
	Status   Status
	Password *memguard.Enclave
}

type Token interface{}

func RandomToken() Token {
	value, _ := uuid.New().Value()
	return value
}

type Provider interface {
	RequestPassword(Request) (Token, error)
	Progress(Token) (Report, error)
}

type staticProvider struct {
	password *memguard.Enclave
}

func (p *staticProvider) RequestPassword(_ Request) (Token, error) {
	token, err := uuid.New().Value()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *staticProvider) Progress(token Token) (Report, error) {
	return Report{
		Status:   Approved,
		Password: p.password,
	}, nil
}

// PromptProvider prompts for a PIN once (on the first Progress call) and caches the result
// in a memguard enclave. Subsequent calls return the cached PIN without re-prompting.
type PromptProvider struct {
	name   string
	mu     sync.Mutex
	tokens map[Token]bool
	cached *memguard.Enclave // set after first successful prompt
}

func (p *PromptProvider) RequestPassword(_ Request) (Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	token := RandomToken()
	p.tokens[token] = true
	return token, nil
}

func (p *PromptProvider) Progress(token Token) (Report, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, ok := p.tokens[token]
	if !ok {
		return Report{}, ErrBadToken
	}
	delete(p.tokens, token)

	if p.cached == nil {
		// First call: prompt interactively and cache the result.
		fmt.Fprintf(os.Stderr, "Enter PIN for %q: ", p.name)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return Report{}, fmt.Errorf("failed to read PIN: %w", err)
		}
		if len(raw) == 0 {
			return Report{}, errors.New("PIN cannot be empty")
		}
		enclave := memguard.NewEnclave(raw)
		for i := range raw {
			raw[i] = 0
		}
		if enclave == nil {
			return Report{}, errors.New("failed to create memguard enclave")
		}
		p.cached = enclave
	}

	return Report{
		Status:   Approved,
		Password: p.cached,
	}, nil
}

type ProviderDescriptor struct {
	New func(viper.Viper) (Provider, error)
}

var registeredProviders = map[string]ProviderDescriptor{}

func RegisterProvider(id string, desc ProviderDescriptor) {
	// TODO - check for conflict
	registeredProviders[id] = desc
}

func GetProvider(id string, config viper.Viper) (Provider, error) {
	providerDesc, ok := registeredProviders[id]
	if !ok {
		return nil, ErrProviderNotFound
	}

	provider, err := providerDesc.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create %q provider: %w", id, err)
	}

	return provider, nil
}

// init registers the default password providers.
func init() {
	// Register static password provider
	RegisterProvider("static", ProviderDescriptor{
		New: func(v viper.Viper) (Provider, error) {
			// Try to get file from config.file first
			filePath := v.GetString("config.file")
			if filePath == "" {
				filePath = v.GetString("file")
			}

			if len(filePath) > 0 { // password file
				// Read entire file into memory
				data, err := os.ReadFile(filePath)
				if err != nil {
					return nil, err
				}
				if len(data) == 0 {
					return nil, errors.New("password file is empty")
				}
				// Create enclave directly from bytes
				passwordEnclave := memguard.NewEnclave(data)
				if passwordEnclave == nil {
					return nil, errors.New("failed to create password enclave")
				}
				return &staticProvider{password: passwordEnclave}, nil
			}
			return nil, errors.New("no password source configured")
		},
	})

	// Register prompt password provider
	RegisterProvider("prompt", ProviderDescriptor{
		New: func(v viper.Viper) (Provider, error) {
			return &PromptProvider{name: v.GetString("_name"), tokens: map[Token]bool{}}, nil
		},
	})

	// Register terminal password provider (alias for prompt)
	RegisterProvider("terminal", ProviderDescriptor{
		New: func(v viper.Viper) (Provider, error) {
			return &PromptProvider{name: v.GetString("_name"), tokens: map[Token]bool{}}, nil
		},
	})
}

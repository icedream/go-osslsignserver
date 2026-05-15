package prompt

import (
	"fmt"
	"os"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

// ReadPINFromTerminal prompts the user for a PIN and returns it as a memguard enclave.
func ReadPINFromTerminal(prompt string) (*memguard.Enclave, error) {
	fmt.Fprint(os.Stderr, prompt)

	// Read password from stdin
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Fprintln(os.Stderr) // New line after password input

	if len(raw) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Create a memguard enclave from the raw bytes
	enclave := memguard.NewEnclave(raw)
	if enclave == nil {
		return nil, fmt.Errorf("failed to create memguard enclave")
	}

	// Zero raw slice immediately
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	return enclave, nil
}

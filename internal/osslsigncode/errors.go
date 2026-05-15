package osslsigncode

import "fmt"

type Error struct {
	Result
	ExitCode int
}

func (e Error) Error() string {
	return fmt.Sprintf("osslsigncode returned error code %d", e.ExitCode)
}

type Result struct {
	Stderr string
	Stdout string
}

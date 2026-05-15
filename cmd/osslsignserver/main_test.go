package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLogLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			level, err := parseLogLevel(input)
			require.NoError(t, err)
			require.Equal(t, expected, level)
		})
	}
}

func TestParseLogLevelRejectsInvalidValue(t *testing.T) {
	level, err := parseLogLevel("verbose")
	require.Error(t, err)
	require.Zero(t, level)
}

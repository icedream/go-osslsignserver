package osslsigncode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParam(t *testing.T) {
	testParam := osslsigncodeParam{
		Key:   "key",
		Value: "value",
	}
	require.Equal(t, testParam.Args(), []string{"-key", "value"})

	testParam = osslsigncodeParam{
		Key: "key",
	}
	require.Equal(t, testParam.Args(), []string{"-key", ""})

	testParam = osslsigncodeParam{
		Value: "value",
	}
	require.Equal(t, testParam.Args(), []string{"value"})

	testParam = osslsigncodeParam{}
	require.Equal(t, testParam.Args(), []string{""})
}

func TestParams(t *testing.T) {
	a := osslsigncodeParams{}

	a.Add("key", "value")
	require.Len(t, a, 1)

	a.AddOptional("key2", "")
	require.Len(t, a, 1)

	a.AddOptional("key2", "value")
	require.Len(t, a, 2)

	a.AddMultiple("key3", "a", "b")
	require.Len(t, a, 4)

	a.AddSwitch("key4", false)
	require.Len(t, a, 4)

	a.AddSwitch("key5", true)
	require.Len(t, a, 5)

	a.Append(osslsigncodeParams{
		osslsigncodeParam{Key: "key6", Value: "value6"},
		osslsigncodeParam{Key: "key7", Switch: true},
		osslsigncodeParam{Key: "key8", Value: ""},
	})
	require.Len(t, a, 8)

	args := a.Args()
	require.Equal(t, []string{
		"-key", "value",
		"-key2", "value",
		"-key3", "a",
		"-key3", "b",
		"-key5",
		"-key6", "value6",
		"-key7",
		"-key8", "",
	}, args)
}

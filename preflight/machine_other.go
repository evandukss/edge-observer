//go:build !linux

package preflight

import (
	"errors"
	"runtime"
)

func machine() (string, error) {
	return "", errors.New("uname is not read on " + runtime.GOOS)
}

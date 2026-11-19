//go:build !linux && !darwin

package sandbox

import "errors"

func defaultGateway() (string, error) {
	return "", errors.New("not implemented on this platform")
}

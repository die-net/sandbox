//go:build !linux && !darwin

package sandbox

import "errors"

// Probe is not implemented off Linux yet.
func Probe() (Report, error) {
	return Report{}, errors.New("sandbox: the backend for this platform is not implemented yet")
}

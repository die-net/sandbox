//go:build !linux && !darwin

package sandbox

import "errors"

// currentHost has no host to describe here, since no backend runs.
func currentHost() (hostView, error) { return hostView{}, errors.ErrUnsupported }

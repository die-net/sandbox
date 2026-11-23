//go:build !linux && !darwin

package sandbox

// platformHints is empty where nothing finds targets for the child.
func platformHints(*Spec) checkHints { return checkHints{} }

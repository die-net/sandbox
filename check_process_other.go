//go:build !linux && !darwin

package sandbox

func checkProcesses(*checkEnv) []Result {
	names := []string{"proc.visible", "proc.signal", "proc.trace", "proc.environ"}
	res := make([]Result, 0, len(names))
	for _, n := range names {
		res = append(res, skipped(n, "not implemented on this platform yet"))
	}
	return res
}

//go:build !linux && !darwin

package sandbox

func checkProcesses(*checkEnv) []Result {
	var res []Result
	for _, n := range []string{"proc.visible", "proc.signal", "proc.trace", "proc.environ"} {
		res = append(res, skipped(n, "not implemented on this platform yet"))
	}
	return res
}

package sandbox

import "os"

// currentHost returns what prepare needs of the host this process runs on:
// its accounts' homes, which the account the program runs as may add to when
// a directory service has it, and its mount table.
func currentHost() (hostView, error) {
	homes, err := hostHomes()
	if err != nil {
		return hostView{}, err
	}
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	mounts, err := hostMounts()
	if err != nil {
		return hostView{}, err
	}
	return hostView{fs: os.DirFS("/"), homes: homes, mounts: mounts, cover: defaultCover}, nil
}

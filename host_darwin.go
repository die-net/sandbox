package sandbox

import "os"

// currentHost returns what prepare needs of the host this process runs on:
// its accounts' homes, which the account the program runs as may add to when
// a directory service has it, and the links that lead to a default cover.
func currentHost() (hostView, error) {
	homes, err := hostHomes()
	if err != nil {
		return hostView{}, err
	}
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	return hostView{fs: os.DirFS("/"), homes: homes, cover: defaultCover, aliases: coverAliases}, nil
}

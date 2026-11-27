//go:build linux || darwin

package sandbox

import (
	"bytes"
	"sync"
)

// syncBuffer is a writer that is not an *os.File, so exec copies to it from a
// goroutine of its own. Its lock lets a test read what has been written while
// the command still runs, which a bytes.Buffer can't do without a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns what has been written so far, while writes may go on.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

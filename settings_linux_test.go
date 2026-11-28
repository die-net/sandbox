package sandbox

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The settings reach the reaper whole, in as many messages as they take, also
// through a socket whose send buffer is far smaller than maxMessage, and at
// lengths that fill the last message exactly.
func TestSettingsMessages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		sndbuf int // 0 leaves the default
		arg    int // the length of the command's one argument
	}{
		{"one message", 0, 10},
		{"many messages", 0, 300_000},
		{"a small buffer", 4096, 100_000},
		{"a last message filled", 0, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent, child, err := socketpair()
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			if tc.sndbuf > 0 {
				if err := unix.SetsockoptInt(int(parent.Fd()), unix.SOL_SOCKET, unix.SO_SNDBUF, tc.sndbuf); err != nil {
					t.Fatal(err)
				}
			}
			n := tc.arg
			if n < 0 {
				n = fillingArg(t)
			}
			want := stageSettings{Command: toByteArgs([]string{"/bin/true", strings.Repeat("x", n)}), Kernel: KernelStrict}
			body, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if tc.arg < 0 && len(body)%(maxMessage-1) != 0 {
				t.Fatalf("the body is %d bytes, which doesn't fill its last message", len(body))
			}
			// The sender closes its end when it is done, so that a send that
			// fails ends the read with an error rather than a wait.
			sent := make(chan error, 1)
			go func() {
				err := sendSettings(parent, body)
				sent <- errors.Join(err, parent.Close())
			}()
			// A receiver that stops early fails the test here, and the
			// deferred close of its end then ends a send still blocked on it.
			got, err := receiveSettings(int(child.Fd()))
			if err != nil {
				t.Fatalf("receive: %v", err)
			}
			if err := <-sent; err != nil {
				t.Fatalf("send: %v", err)
			}
			if !slices.Equal(got.Command.strings(), want.Command.strings()) || got.Kernel != want.Kernel {
				t.Errorf("the settings arrived changed: %d arguments, kernel %q", len(got.Command), got.Kernel)
			}
		})
	}
}

// fillingArg returns the length of an argument that makes the settings of
// TestSettingsMessages fill their last message exactly, at the default
// buffer: the JSON is a fixed part and the argument in base64, which is four
// bytes for each three, so a length is found for the second multiple of a
// message's payload that the fixed part leaves a multiple of four of.
func fillingArg(t *testing.T) int {
	t.Helper()
	body, err := json.Marshal(stageSettings{Command: toByteArgs([]string{"/bin/true", ""}), Kernel: KernelStrict})
	if err != nil {
		t.Fatal(err)
	}
	for m := 2; ; m++ {
		if rest := m*(maxMessage-1) - len(body); rest%4 == 0 {
			return rest / 4 * 3
		}
	}
}

// The reaper refuses settings that aren't whole, aren't framed as sendSettings
// frames them, or carry no command, whoever wrote them: the stage is found by
// a variable, so it can be started on a socket the library didn't set up.
func TestSettingsRefusals(t *testing.T) {
	t.Parallel()
	body := func(s stageSettings) []byte {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	last := func(b []byte) []byte { return append([]byte{settingsLast}, b...) }
	good := body(stageSettings{Command: toByteArgs([]string{"/bin/true"})})
	for _, tc := range []struct {
		name string
		msgs [][]byte // each written as one message, then the socket is closed
		want string   // in the error, or "" for none
	}{
		{"whole", [][]byte{last(good)}, ""},
		{"in two", [][]byte{append([]byte{settingsMore}, good[:5]...), last(good[5:])}, ""},
		{"a lead byte that says neither", [][]byte{append([]byte{2}, good...)}, "starts with 2"},
		{"no command", [][]byte{last(body(stageSettings{}))}, "no command"},
		{"an empty command", [][]byte{last(body(stageSettings{Command: toByteArgs([]string{""})}))}, "no command"},
		{"not JSON", [][]byte{last([]byte("{"))}, "read the settings"},
		{"the end before the last", [][]byte{append([]byte{settingsMore}, good...)}, "empty or too long"},
		{"nothing", nil, "empty or too long"},
		{"a message too long", [][]byte{last(make([]byte, maxMessage))}, "empty or too long"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent, child, err := socketpair()
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			for _, m := range tc.msgs {
				if _, err := parent.Write(m); err != nil {
					t.Fatal(err)
				}
			}
			_ = parent.Close()
			_, err = receiveSettings(int(child.Fd()))
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("receiveSettings = %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("receiveSettings = %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// Start takes the reaper's second message for what it says, refuses one that
// says nothing or can't be read, and takes the socket's end in its place as
// the command's start, which Wait then reports on.
func TestReceiveStarted(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		msg  []byte // written as one message, or none if nil, then the socket is closed
		want string // in the error, or "" for none
	}{
		{"started", []byte(`{"started":true}`), ""},
		{"the end of the socket", nil, ""},
		{"the start's error", []byte(`{"error":"start command: exec format error"}`), "exec format error"},
		{"nothing said", []byte(`{}`), "says nothing"},
		{"not JSON", []byte(`{`), "malformed"},
		{"too long", make([]byte, maxMessage+1), "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent, child, err := socketpair()
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			if tc.msg != nil {
				if _, err := parent.Write(tc.msg); err != nil {
					t.Fatal(err)
				}
			}
			_ = parent.Close()
			err = receiveStarted(child)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("receiveStarted = %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("receiveStarted = %v, want an error with %q", err, tc.want)
			}
		})
	}
}

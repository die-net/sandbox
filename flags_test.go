package sandbox

import (
	"flag"
	"io"
	"slices"
	"testing"
)

func TestRegisterFlags(t *testing.T) {
	t.Parallel()
	var spec Spec
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	spec.RegisterFlags(fs)
	args := []string{"-home", "/h", "-write", "/a", "-write", "/b", "-read", "/r", "-cover", "/c", "-kernel", "nested", "--", "sh", "-c", "true"}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if spec.Home != "/h" || spec.Kernel != KernelNested {
		t.Errorf("Home = %q, Kernel = %q", spec.Home, spec.Kernel)
	}
	for name, got := range map[string][]string{"write": spec.Write, "read": spec.Read, "cover": spec.Cover} {
		want := map[string][]string{"write": {"/a", "/b"}, "read": {"/r"}, "cover": {"/c"}}[name]
		if !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !slices.Equal(fs.Args(), []string{"sh", "-c", "true"}) {
		t.Errorf("command = %q", fs.Args())
	}
}

func TestNetworkFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		want Network
		ok   bool
	}{
		{nil, NetworkNone, true},
		{[]string{"-network", "none"}, NetworkNone, true},
		{[]string{"-network", "host"}, NetworkHost, true},
		{[]string{"-network", "all"}, NetworkNone, false},
	} {
		var spec Spec
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		spec.RegisterFlags(fs)
		err := fs.Parse(tc.args)
		if (err == nil) != tc.ok || spec.Network != tc.want {
			t.Errorf("%q: Network = %v, err = %v; want %v, ok %v", tc.args, spec.Network, err, tc.want, tc.ok)
		}
	}
}

func TestKernelFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"strict", true},
		{"nested", true},
		{"open", true},
		{"", false},
		{"Strict", false},
		{"none", false},
	} {
		var spec Spec
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		spec.RegisterFlags(fs)
		err := fs.Parse([]string{"-kernel", tc.value})
		if (err == nil) != tc.ok {
			t.Errorf("-kernel %q: err = %v, want ok %v", tc.value, err, tc.ok)
		}
	}
}

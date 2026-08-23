package wireguard

import "testing"

// resetAWG returns package state to "SetAWGParams was never called" and drops
// the cached environment read, so each test observes its own t.Setenv value.
func resetAWG(t *testing.T) {
	t.Helper()
	awgParams.Lock()
	awgParams.uapi = ""
	awgParams.set = false
	awgParams.envOnce = nil
	awgParams.env = ""
	awgParams.Unlock()
}

func TestAWGUAPILines_NoEnvNoSetter(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "")
	if got := awgUAPILines(); got != "" {
		t.Fatalf("want vanilla WireGuard (empty), got %q", got)
	}
}

func TestAWGUAPILines_EnvWithEscapedNewlines(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, `jc=4\njmin=40\njmax=70\n`)
	want := "jc=4\njmin=40\njmax=70\n"
	if got := awgUAPILines(); got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestAWGUAPILines_EnvWithRealNewlines(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "jc=4\njmin=40\n")
	want := "jc=4\njmin=40\n"
	if got := awgUAPILines(); got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestAWGUAPILines_EnvMissingTrailingNewline(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "jc=4\njmin=40")
	want := "jc=4\njmin=40\n"
	if got := awgUAPILines(); got != want {
		t.Fatalf("UAPI lines must be newline-terminated: want %q, got %q", want, got)
	}
}

// awgUAPILines sits on the packet receive path (see bind.go), so the
// environment must be read once and cached, not re-read per packet.
func TestAWGUAPILines_EnvReadOnlyOnce(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "jc=4\n")
	if got := awgUAPILines(); got != "jc=4\n" {
		t.Fatalf("first read: want %q, got %q", "jc=4\n", got)
	}

	t.Setenv(awgParamsEnvKey, "jc=9\n")
	if got := awgUAPILines(); got != "jc=4\n" {
		t.Fatalf("environment must be cached after the first read, got %q", got)
	}
}

// Android calls SetAWGParams and relies on "" meaning vanilla WireGuard.
// The environment must not override that, or switching to a non-AWG server
// would silently stay obfuscated.
func TestSetAWGParamsWinsOverEnv(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "jc=9\n")

	SetAWGParams("jc=1\n")
	if got := awgUAPILines(); got != "jc=1\n" {
		t.Fatalf("explicit setter must win, got %q", got)
	}

	SetAWGParams("")
	if got := awgUAPILines(); got != "" {
		t.Fatalf(`SetAWGParams("") must mean vanilla even with env set, got %q`, got)
	}
}

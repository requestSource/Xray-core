package wireguard

import (
	"os"
	"strings"
	"sync"
)

// AmneziaWG (AWG) support for the WireGuard outbound.
//
// The device this outbound drives is amneziawg-go, imported directly by the
// files in this package, so no code here changes: amneziawg-go behaves exactly
// like upstream wireguard-go until the obfuscation parameters
// (jc/jmin/jmax/s1/s2/h1..h4) arrive over UAPI. Those parameters are
// device-level, so they must be written before the first peer line — see
// createIPCRequest.
//
// They are passed out-of-band rather than through DeviceConfig on purpose:
// carrying them in the proto would mean regenerating config.pb.go and teaching
// infra/conf about new JSON fields, i.e. a much larger patch to rebase onto
// every upstream release.
var awgParams struct {
	sync.RWMutex
	uapi string
	set  bool

	// envOnce guards the single read of awgParamsEnvKey. awgUAPILines is on
	// the packet receive path (see bind.go), so the environment must not be
	// touched per packet.
	envOnce *sync.Once
	env     string
}

// awgParamsEnvKey is the fallback channel for processes that cannot call
// SetAWGParams: the Windows client runs xray as a SEPARATE process, so the Go
// API never reaches it. The value is the same UAPI lines, and both real
// newlines and two-character backslash-n escapes are accepted — putting a real
// newline into an environment variable on Windows is awkward.
//
// It is consulted only when SetAWGParams has never been called.
const awgParamsEnvKey = "XRAY_AWG_PARAMS"

// SetAWGParams installs the AmneziaWG UAPI lines prepended to every subsequent
// WireGuard device configuration. Pass "" to go back to vanilla WireGuard.
//
// The value must be complete UAPI lines, newline-terminated, e.g.
// "jc=4\njmin=40\njmax=70\ns1=15\ns2=25\nh1=1234567\nh2=2345678\nh3=3456789\nh4=4567890\n".
//
// Process-wide, matching how amneziawg-go itself keeps the message-type
// constants (device.MessageInitiationType and friends are package globals), so
// one process cannot drive two peers with different h1..h4 anyway. Callers
// switching between servers must set this before starting each outbound.
//
// Once called, this wins over awgParamsEnvKey permanently — including with "",
// which stays a deliberate "vanilla WireGuard" and must not silently fall back
// to the environment.
func SetAWGParams(uapi string) {
	awgParams.Lock()
	awgParams.uapi = uapi
	awgParams.set = true
	awgParams.Unlock()
}

func awgUAPILines() string {
	awgParams.RLock()
	uapi, set, once := awgParams.uapi, awgParams.set, awgParams.envOnce
	awgParams.RUnlock()
	if set {
		return uapi
	}

	if once == nil {
		awgParams.Lock()
		if awgParams.envOnce == nil {
			awgParams.envOnce = new(sync.Once)
		}
		once = awgParams.envOnce
		awgParams.Unlock()
	}
	once.Do(func() {
		env := awgParamsFromEnv()
		awgParams.Lock()
		awgParams.env = env
		awgParams.Unlock()
	})

	awgParams.RLock()
	defer awgParams.RUnlock()
	return awgParams.env
}

// awgParamsFromEnv normalises awgParamsEnvKey into UAPI lines: backslash-n
// escapes become real newlines and the result is newline-terminated. Returns ""
// for an unset or blank value, i.e. vanilla WireGuard.
func awgParamsFromEnv() string {
	raw := strings.ReplaceAll(os.Getenv(awgParamsEnvKey), `\n`, "\n")
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if !strings.HasSuffix(raw, "\n") {
		raw += "\n"
	}
	return raw
}

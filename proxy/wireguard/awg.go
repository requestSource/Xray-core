package wireguard

import "sync"

// AmneziaWG (AWG) support for the WireGuard outbound.
//
// The device this outbound drives is amneziawg-go, injected at build time via
//
//	replace golang.zx2c4.com/wireguard => github.com/amnezia-vpn/amneziawg-go
//
// so no code here changes: amneziawg-go behaves exactly like upstream
// wireguard-go until the obfuscation parameters (jc/jmin/jmax/s1/s2/h1..h4)
// arrive over UAPI. Those parameters are device-level, so they must be written
// before the first peer line — see createIPCRequest.
//
// They are passed out-of-band rather than through DeviceConfig on purpose:
// carrying them in the proto would mean regenerating config.pb.go and teaching
// infra/conf about new JSON fields, i.e. a much larger patch to rebase onto
// every upstream release.
var awgParams struct {
	sync.RWMutex
	uapi string
}

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
func SetAWGParams(uapi string) {
	awgParams.Lock()
	awgParams.uapi = uapi
	awgParams.Unlock()
}

func awgUAPILines() string {
	awgParams.RLock()
	defer awgParams.RUnlock()
	return awgParams.uapi
}

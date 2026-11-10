package wireguard

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

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

func TestAWGUAPILines_EnvWhitespaceOnly(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "   \n\t ")
	if got := awgUAPILines(); got != "" {
		t.Fatalf("a blank value must mean vanilla WireGuard, got %q", got)
	}
}

// The cached environment read is a double-checked lock: envOnce is read under
// RLock and created under Lock. Hammer the first call from many goroutines so
// `go test -race` actually exercises that branch.
func TestAWGUAPILines_ConcurrentFirstRead(t *testing.T) {
	resetAWG(t)
	t.Setenv(awgParamsEnvKey, "jc=4\n")

	const goroutines = 32
	got := make([]string, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			<-start
			got[i] = awgUAPILines()
		}()
	}
	close(start)
	wg.Wait()

	for i, v := range got {
		if v != "jc=4\n" {
			t.Fatalf("goroutine %d saw %q, want %q", i, v, "jc=4\n")
		}
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

// ipcWithPeer builds an outbound UAPI request the way NewClient does: the AWG
// lines (awgForDevice) go between private_key and the first peer.
func ipcWithPeer(b *bind) string {
	key := strings.Repeat("11", 32)
	peer := strings.Repeat("22", 32)
	return "private_key=" + key + "\n" + awgForDevice(b) +
		"public_key=" + peer + "\nallowed_ip=0.0.0.0/0\n"
}

// A stray blank line ends a UAPI set transaction and a CR breaks the value
// parse, so either used to drop the peer that follows the AWG lines.
func TestAWGParamsNormalizedKeepPeers(t *testing.T) {
	for name, uapi := range map[string]string{
		"double newline":  "jc=4\njmin=40\njmax=70\n\n",
		"crlf":            "jc=4\r\njmin=40\r\njmax=70\r\n",
		"crlf blank line": "jc=4\r\njmin=40\r\njmax=70\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			resetAWG(t)
			SetAWGParams(uapi)
			b := &bind{}
			tn, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, nil)
			if err != nil {
				t.Fatal(err)
			}
			dev := device.NewDevice(newblockup(tn), b, device.NewLogger(device.LogLevelSilent, ""))
			defer dev.Close()
			if err := dev.IpcSet(ipcWithPeer(b)); err != nil {
				t.Fatalf("IpcSet: %v", err)
			}
			got, err := dev.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, "public_key="+strings.Repeat("22", 32)) {
				t.Fatalf("peer dropped after AWG lines; device state:\n%s", got)
			}
		})
	}
}

type capturePacketConn struct {
	net.PacketConn
	got [][]byte
}

func (c *capturePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.got = append(c.got, append([]byte(nil), p...))
	return len(p), nil
}

func sendOne(t *testing.T, b *bind) []byte {
	t.Helper()
	c := &capturePacketConn{}
	b.PacketConn = c
	b.reserved = []byte{7, 8, 9}
	ep := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}
	if err := b.Send([][]byte{{1, 0xa1, 0xa2, 0xa3, 5}}, ep); err != nil {
		t.Fatal(err)
	}
	return c.got[0]
}

func recvOne(t *testing.T, b *bind) []byte {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b.PacketConn = nil // sendOne may have left its capture conn
	b.listenFunc = func(context.Context) (net.PacketConn, error) { return l, nil }
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s, err := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Write([]byte{1, 0xa1, 0xa2, 0xa3, 5}); err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if _, err := fns[0](bufs, sizes, eps); err != nil {
		t.Fatal(err)
	}
	return bufs[0][:sizes[0]]
}

func newDeviceBind(t *testing.T, uapi string) *bind {
	t.Helper()
	SetAWGParams(uapi)
	b := &bind{ctx: context.Background()}
	awgForDevice(b)
	return b
}

func TestAWGBindSendReserved(t *testing.T) {
	resetAWG(t)
	if got := sendOne(t, newDeviceBind(t, "jc=4\n")); !bytes.Equal(got[1:4], []byte{0xa1, 0xa2, 0xa3}) {
		t.Fatalf("AWG active: bytes 1-3 must stay, got % x", got)
	}
	if got := sendOne(t, newDeviceBind(t, "")); !bytes.Equal(got[1:4], []byte{7, 8, 9}) {
		t.Fatalf("no AWG: reserved must be written, got % x", got)
	}
}

func TestAWGBindRecvReserved(t *testing.T) {
	resetAWG(t)
	if got := recvOne(t, newDeviceBind(t, "jc=4\n")); !bytes.Equal(got[1:4], []byte{0xa1, 0xa2, 0xa3}) {
		t.Fatalf("AWG active: bytes 1-3 must stay, got % x", got)
	}
	if got := recvOne(t, newDeviceBind(t, "")); !bytes.Equal(got[1:4], []byte{0, 0, 0}) {
		t.Fatalf("no AWG: bytes 1-3 must be zeroed, got % x", got)
	}
}

// The AWG decision belongs to the device: a later SetAWGParams (the next
// server's connect) must not change a device built before it.
func TestAWGBindDecidedPerDevice(t *testing.T) {
	resetAWG(t)
	vanilla := newDeviceBind(t, "")
	SetAWGParams("jc=4\n")
	if got := sendOne(t, vanilla); !bytes.Equal(got[1:4], []byte{7, 8, 9}) {
		t.Fatalf("vanilla device changed by later SetAWGParams (send), got % x", got)
	}
	if got := recvOne(t, vanilla); !bytes.Equal(got[1:4], []byte{0, 0, 0}) {
		t.Fatalf("vanilla device changed by later SetAWGParams (recv), got % x", got)
	}

	awg := newDeviceBind(t, "jc=4\n")
	SetAWGParams("")
	if got := sendOne(t, awg); !bytes.Equal(got[1:4], []byte{0xa1, 0xa2, 0xa3}) {
		t.Fatalf(`AWG device changed by later SetAWGParams("") (send), got % x`, got)
	}
	if got := recvOne(t, awg); !bytes.Equal(got[1:4], []byte{0xa1, 0xa2, 0xa3}) {
		t.Fatalf(`AWG device changed by later SetAWGParams("") (recv), got % x`, got)
	}
}

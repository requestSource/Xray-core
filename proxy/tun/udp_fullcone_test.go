package tun

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPNewSession(b *testing.B) {
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		u.HandlePacket(src, dst, &buf.Buffer{})
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		b := buf.New()
		b.WriteByte(byte(i))
		if !q.push(b) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		b, ok := q.pop()
		if !ok || b.Byte(0) != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, b, ok)
		}
		b.Release()
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&buf.Buffer{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&buf.Buffer{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

// TestStackCloseEndsUDPFlows: Close must wake every full-cone flow reader, or
// the outbound behind it keeps its socket until the idle timeout.
func TestStackCloseEndsUDPFlows(t *testing.T) {
	ended := make(chan struct{}, 4)
	s := &stack{}
	s.udp = newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		b := make([]byte, 64)
		for {
			if _, err := conn.Read(b); err != nil {
				ended <- struct{}{}
				return
			}
		}
	}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	for i := 0; i < 4; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, 0, 0, byte(i + 1)}), net.Port(40000+i))
		b := buf.New()
		b.WriteByte(1)
		s.udp.HandlePacket(src, dst, b)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		select {
		case <-ended:
		case <-time.After(2 * time.Second):
			t.Fatalf("flow %d still open after Close", i)
		}
	}
	// a packet that races Close does not open a new flow
	s.udp.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 9}), net.Port(40009)), dst, buf.New())
	s.udp.RLock()
	n := len(s.udp.udpConns)
	s.udp.RUnlock()
	if n != 0 {
		t.Fatalf("%d flows opened after Close", n)
	}
}

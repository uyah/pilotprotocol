// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func testFrame(t *testing.T, n int) []byte {
	t.Helper()
	f := make([]byte, n)
	if _, err := rand.Read(f); err != nil {
		t.Fatal(err)
	}
	return f
}

var fragFrom = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}

// A full 4096-byte segment sealed as PILS is 4166 bytes; every fragment of it,
// with the 9-byte relay header, must fit 1232 bytes (IPv6 minimum MTU minus
// IPv6/UDP headers).
func TestFragmentFrameFitsMinimumMTU(t *testing.T) {
	t.Parallel()
	frame := testFrame(t, MaxSegmentSize+34+36)
	frags := fragmentFrame(7, 1, frame)
	if len(frags) < 2 {
		t.Fatalf("got %d fragments, want several", len(frags))
	}
	for i, f := range frags {
		if len(f)+9 > 1232 {
			t.Fatalf("fragment %d is %d bytes (+9 relay) > 1232", i, len(f))
		}
	}
	if small := fragmentFrame(7, 1, frame[:fragMaxFrame]); len(small) != 1 || !bytes.Equal(small[0], frame[:fragMaxFrame]) {
		t.Fatal("a frame that fits one datagram must be sent unchanged")
	}
}

func TestFragmentReassembleOrders(t *testing.T) {
	t.Parallel()
	frame := testFrame(t, 5000)
	frags := fragmentFrame(7, 42, frame)
	for name, order := range map[string][]int{"in order": {0, 1, 2, 3, 4}, "reversed": {4, 3, 2, 1, 0}, "mixed": {2, 0, 4, 1, 3}} {
		r := newFragReassembler()
		var got []byte
		for i, idx := range order {
			out := r.add(frags[idx][4:], fragFrom, 0, time.Now())
			if i < len(order)-1 && out != nil {
				t.Fatalf("%s: frame returned before all fragments arrived", name)
			}
			got = out
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("%s: reassembled frame differs", name)
		}
		if len(r.pending) != 0 || len(r.perSender) != 0 {
			t.Fatalf("%s: state left after completion", name)
		}
	}
}

func TestFragmentDuplicateAndMissing(t *testing.T) {
	t.Parallel()
	frame := testFrame(t, 3000)
	frags := fragmentFrame(7, 1, frame)
	r := newFragReassembler()
	now := time.Now()
	r.add(frags[0][4:], fragFrom, 0, now)
	if out := r.add(frags[0][4:], fragFrom, 0, now); out != nil {
		t.Fatal("duplicate fragment completed a frame")
	}
	if r.Dropped.Load() != 1 {
		t.Fatalf("duplicate not counted as dropped: %d", r.Dropped.Load())
	}
	// The last fragment never arrives: the partial frame expires.
	r.add(frags[1][4:], fragFrom, 0, now)
	// A fragment of another frame after the timeout triggers the sweep.
	other := fragmentFrame(7, 2, testFrame(t, 3000))
	r.add(other[0][4:], fragFrom, 0, now.Add(2*fragTimeout))
	if _, ok := r.pending[fragKey{path: fragFrom.String(), sender: 7, id: 1}]; ok || len(r.pending) != 1 {
		t.Fatalf("expired partial frame kept (%d pending)", len(r.pending))
	}
}

func TestFragmentRelaySenderMustMatch(t *testing.T) {
	t.Parallel()
	frags := fragmentFrame(7, 1, testFrame(t, 3000))
	r := newFragReassembler()
	if out := r.add(frags[0][4:], nil, 8, time.Now()); out != nil || len(r.pending) != 0 {
		t.Fatal("fragment claiming another sender than the beacon reported was accepted")
	}
	for _, f := range frags[:len(frags)-1] {
		r.add(f[4:], nil, 7, time.Now())
	}
	if out := r.add(frags[len(frags)-1][4:], nil, 7, time.Now()); out == nil {
		t.Fatal("relay fragments from the reported sender were not reassembled")
	}
}

func TestFragmentPendingLimits(t *testing.T) {
	t.Parallel()
	r := newFragReassembler()
	now := time.Now()
	for id := uint32(0); id < fragMaxPendingPerSender+10; id++ {
		f := fragmentFrame(7, id, testFrame(t, 3000))
		r.add(f[0][4:], fragFrom, 0, now)
	}
	if got := r.perSender[7]; got != fragMaxPendingPerSender {
		t.Fatalf("per-sender pending = %d, want cap %d", got, fragMaxPendingPerSender)
	}
	if r.Dropped.Load() != 10 {
		t.Fatalf("dropped = %d, want 10", r.Dropped.Load())
	}
}

func TestFragmentRejectsMalformed(t *testing.T) {
	t.Parallel()
	r := newFragReassembler()
	f := fragmentFrame(7, 1, testFrame(t, 3000))[0]
	bad := append([]byte(nil), f[4:]...)
	bad[9] = 1 // count < 2
	if r.add(bad, fragFrom, 0, time.Now()) != nil || len(r.pending) != 0 {
		t.Fatal("fragment with count 1 accepted")
	}
	bad[9], bad[8] = 3, 5 // index >= count
	if r.add(bad, fragFrom, 0, time.Now()) != nil || len(r.pending) != 0 {
		t.Fatal("fragment with index >= count accepted")
	}
	if fragmentFrame(7, 1, make([]byte, fragMaxPayload*fragMaxCount+1)) != nil {
		t.Fatal("frame beyond the fragment limit was split")
	}
}

// readFrameUDP is ReadFromUDP for tests that inspect raw tunnel frames: PILF
// fragments are reassembled, so the caller sees the original frame as if it
// had been sent in one datagram.
func readFrameUDP(c *net.UDPConn, buf []byte) (int, *net.UDPAddr, error) {
	r := newFragReassembler()
	tmp := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDP(tmp)
		if err != nil {
			return 0, from, err
		}
		if n < 4 || [4]byte{tmp[0], tmp[1], tmp[2], tmp[3]} != TunnelMagicFrag {
			return copy(buf, tmp[:n]), from, nil
		}
		if full := r.add(tmp[4:n], from, 0, time.Now()); full != nil {
			return copy(buf, full), from, nil
		}
	}
}

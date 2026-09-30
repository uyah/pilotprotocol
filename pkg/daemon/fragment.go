// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel-level fragmentation.
//
// A stream segment can be up to MaxSegmentSize (4096) bytes, so a sealed
// tunnel frame can be ~4.2 KB. Sent as one UDP datagram it needs IP
// fragmentation, and many paths (VPNs, carrier-grade NAT, mobile networks)
// drop IP fragments: every large frame is then lost and the same frame is
// retransmitted forever. Instead of shrinking segments (which changes window,
// congestion and Nagle behaviour), the tunnel splits a frame that does not fit
// one path-MTU-safe datagram into PILF fragments and the receiver reassembles
// the original frame before the normal magic dispatch. Everything above the
// tunnel (segments, windows, congestion control, encryption) is unchanged.
//
// Fragment frame: [PILF][senderNodeID(4)][fragID(4)][index(1)][count(1)][payload]
//
// The header is not authenticated. A reassembled frame goes through exactly
// the same dispatch and checks as a frame received in one datagram (AEAD for
// PILS, signatures for PILA, the existing policies for PILK and plaintext), so
// fragmentation adds no way around them. Admission is accounted per actual
// source (remote UDP address, or the beacon-reported relay sender), never per
// the claimed sender ID, so a third party cannot use up another peer's quota;
// memory is bounded by the limits below.
// Both peers must support PILF: a peer without it drops the fragments, so
// frames larger than one fragment do not reach it.

// TunnelMagicFrag marks a tunnel fragment.
var TunnelMagicFrag = [4]byte{'P', 'I', 'L', 'F'}

const (
	fragHeaderLen = 4 + 4 + 4 + 1 + 1
	// fragMaxFrame is the largest frame sent unfragmented: with the 9-byte
	// beacon relay header it is 1232 bytes of UDP payload, which fits the
	// IPv6 minimum MTU of 1280 with IPv6/UDP headers.
	fragMaxFrame = 1232 - 9
	// fragMaxPayload keeps each fragment frame within fragMaxFrame.
	fragMaxPayload = fragMaxFrame - fragHeaderLen
	// fragMaxCount bounds a reassembled frame to 64 fragments (~76 KB).
	fragMaxCount = 64
	// fragTimeout drops incomplete frames; the stream layer retransmits.
	fragTimeout = 3 * time.Second
	// fragMaxPending bounds partially reassembled frames overall and per
	// source, so a flood of first fragments cannot grow memory beyond about
	// fragMaxPending*fragMaxCount*fragMaxPayload (~19 MiB).
	fragMaxPending          = 256
	fragMaxPendingPerSource = 32
)

// fragmentFrame splits frame into PILF fragment frames, or returns it
// unchanged when it fits one datagram.
func fragmentFrame(senderNodeID, fragID uint32, frame []byte) [][]byte {
	if len(frame) <= fragMaxFrame {
		return [][]byte{frame}
	}
	count := (len(frame) + fragMaxPayload - 1) / fragMaxPayload
	if count > fragMaxCount {
		return nil // caller treats as unsendable
	}
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		start := i * fragMaxPayload
		end := start + fragMaxPayload
		if end > len(frame) {
			end = len(frame)
		}
		f := make([]byte, fragHeaderLen+end-start)
		copy(f[0:4], TunnelMagicFrag[:])
		binary.BigEndian.PutUint32(f[4:8], senderNodeID)
		binary.BigEndian.PutUint32(f[8:12], fragID)
		f[12] = byte(i)
		f[13] = byte(count)
		copy(f[fragHeaderLen:], frame[start:end])
		out = append(out, f)
	}
	return out
}

type fragKey struct {
	source string // remote UDP address, or "relay:<beacon-reported sender>"
	sender uint32
	id     uint32
}

type fragPartial struct {
	parts   [][]byte
	got     int
	created time.Time
}

// fragReassembler collects PILF fragments into frames.
type fragReassembler struct {
	mu        sync.Mutex
	pending   map[fragKey]*fragPartial
	perSource map[string]int
	lastSweep time.Time
	nextID    atomic.Uint32

	Dropped atomic.Uint64 // fragments dropped (malformed, over limits, expired frames)
}

func newFragReassembler() *fragReassembler {
	r := &fragReassembler{pending: map[fragKey]*fragPartial{}, perSource: map[string]int{}}
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	r.nextID.Store(binary.BigEndian.Uint32(seed[:])) // fresh IDs after a restart
	return r
}

// add consumes one fragment (bytes after the PILF magic). It returns the
// reassembled frame once all fragments of that frame have arrived, else nil.
// relaySender, when non-zero, is the sender reported by the beacon; the
// fragment header must match it.
func (r *fragReassembler) add(data []byte, from *net.UDPAddr, relaySender uint32, now time.Time) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastSweep) > fragTimeout/3 {
		r.sweepLocked(now)
	}
	if len(data) < fragHeaderLen-4+1 {
		r.Dropped.Add(1)
		return nil
	}
	sender := binary.BigEndian.Uint32(data[0:4])
	id := binary.BigEndian.Uint32(data[4:8])
	idx, count := int(data[8]), int(data[9])
	payload := data[10:]
	if count < 2 || count > fragMaxCount || idx >= count || len(payload) > fragMaxPayload ||
		(relaySender != 0 && sender != relaySender) {
		r.Dropped.Add(1)
		return nil
	}
	key := fragKey{sender: sender, id: id}
	if relaySender != 0 {
		key.source = "relay:" + strconv.FormatUint(uint64(relaySender), 10)
	} else {
		if from == nil {
			r.Dropped.Add(1)
			return nil
		}
		key.source = from.String()
	}

	p := r.pending[key]
	if p == nil {
		if len(r.pending) >= fragMaxPending || r.perSource[key.source] >= fragMaxPendingPerSource {
			r.Dropped.Add(1)
			return nil
		}
		p = &fragPartial{parts: make([][]byte, count), created: now}
		r.pending[key] = p
		r.perSource[key.source]++
	}
	if len(p.parts) != count || p.parts[idx] != nil {
		r.Dropped.Add(1) // inconsistent count or duplicate
		return nil
	}
	p.parts[idx] = append([]byte(nil), payload...)
	p.got++
	if p.got < count {
		return nil
	}
	r.deleteLocked(key)
	size := 0
	for _, part := range p.parts {
		size += len(part)
	}
	frame := make([]byte, 0, size)
	for _, part := range p.parts {
		frame = append(frame, part...)
	}
	return frame
}

func (r *fragReassembler) deleteLocked(k fragKey) {
	delete(r.pending, k)
	if r.perSource[k.source]--; r.perSource[k.source] <= 0 {
		delete(r.perSource, k.source)
	}
}

func (r *fragReassembler) sweepLocked(now time.Time) {
	r.lastSweep = now
	for k, p := range r.pending {
		if now.Sub(p.created) > fragTimeout {
			r.deleteLocked(k)
			r.Dropped.Add(uint64(p.got))
		}
	}
}

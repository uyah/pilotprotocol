// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// After an RTO, a partial ACK proves the path works: the backed-off RTO must
// drop back to the computed value and the other segments lost at the timeout
// must be resent right away (within cwnd), instead of one per 10 s RTO.
func TestTimeoutRecoveryPartialAckResendsLostAndResetsBackoff(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }
	old := time.Now().Add(-5 * time.Second)
	c.LastAck = 1000
	for i := 0; i < 8; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{seq: uint32(1000 + i*100), data: make([]byte, 100), sentAt: old, origSentAt: old, attempts: 1})
	}
	// State right after an RTO fired on the first segment.
	c.Unacked[0].attempts = 2
	c.Unacked[0].lastRetx = time.Now()
	c.InRecovery = true
	c.FastRecovery = false
	c.RecoveryPoint = 1800
	c.CongWin = 4 * MaxSegmentSize
	c.SSThresh = 8 * MaxSegmentSize
	c.SRTT = 20 * time.Millisecond
	c.RTTVAR = 5 * time.Millisecond
	c.RTO = 10 * time.Second // backed off

	c.ProcessAck(1100, true) // the retransmitted first segment arrived

	if c.RTO > time.Second {
		t.Fatalf("RTO = %v after progress in timeout recovery, want the computed value (backoff dropped)", c.RTO)
	}
	if len(sent) == 0 {
		t.Fatal("no lost segment resent after a partial ACK in timeout recovery")
	}
	if sent[0] != 1100 {
		t.Fatalf("first resent seq = %d, want 1100 (the new SND.UNA)", sent[0])
	}
	// A second partial ACK right away must not resend the same segments again
	// within the guard (about one SRTT).
	n := len(sent)
	c.ProcessAck(1200, true)
	for _, s := range sent[n:] {
		for _, prev := range sent[:n] {
			if s == prev {
				t.Fatalf("seq %d resent twice within one round trip", s)
			}
		}
	}
}

// Fast recovery is untouched: a partial ACK there keeps the existing
// single-segment NewReno retransmit and does not reset the RTO.
func TestFastRecoveryPartialAckUnchanged(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }
	now := time.Now()
	c.LastAck = 1000
	for i := 0; i < 4; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{seq: uint32(1000 + i*100), data: make([]byte, 100), sentAt: now, origSentAt: now, attempts: 1})
	}
	c.Unacked[0].attempts = 2 // fast-retransmitted: no RTT sample (Karn), so RTO only changes if our code changes it
	c.InRecovery, c.FastRecovery, c.RecoveryPoint = true, true, 1400
	c.CongWin, c.SSThresh = 8*MaxSegmentSize, 4*MaxSegmentSize
	c.RTO = 3 * time.Second
	c.ProcessAck(1100, true)
	if c.RTO != 3*time.Second {
		t.Fatalf("RTO changed in fast recovery: %v", c.RTO)
	}
	if len(sent) != 1 || sent[0] != 1100 {
		t.Fatalf("fast-recovery partial ACK resent %v, want exactly [1100]", sent)
	}
}

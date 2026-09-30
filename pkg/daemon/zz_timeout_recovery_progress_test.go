// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// timeoutRecoveryConn returns a connection right after an RTO fired on the
// first of n segments (100 bytes each, starting at seq 1000).
func timeoutRecoveryConn(t *testing.T, n int) (*Connection, *[]uint32) {
	t.Helper()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }
	old := time.Now().Add(-5 * time.Second)
	c.LastAck = 1000
	for i := 0; i < n; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{seq: uint32(1000 + i*100), data: make([]byte, 100), sentAt: old, origSentAt: old, attempts: 1})
	}
	c.Unacked[0].attempts = 2
	c.Unacked[0].lastRetx = time.Now()
	c.InRecovery, c.FastRecovery = true, false
	c.RecoveryPoint = uint32(1000 + n*100)
	c.SSThresh = 64 * MaxSegmentSize
	c.SRTT, c.RTTVAR = 20*time.Millisecond, 5*time.Millisecond
	c.RTO = 4 * time.Second // backed off
	return c, &sent
}

// A partial ACK in timeout recovery resends the other presumed-lost segments
// right away (after SACK processing), keeps the RTO backoff (no RTT sample),
// and never resends the same segment again within the RTO.
func TestTimeoutRecoveryPartialAckResendsLost(t *testing.T) {
	t.Parallel()
	c, sent := timeoutRecoveryConn(t, 8)
	c.CongWin = 300 // three 100-byte segments

	c.ProcessAck(1100, true)
	if len(*sent) != 0 {
		t.Fatalf("resent %v before SACK processing / RunRecoveryRetransmit", *sent)
	}
	c.RunRecoveryRetransmit()
	if c.RTO != 4*time.Second {
		t.Fatalf("RTO = %v, want the backoff kept (4s) without a valid RTT sample", c.RTO)
	}
	if len(*sent) == 0 || (*sent)[0] != 1100 {
		t.Fatalf("resent %v, want to start at the new SND.UNA 1100", *sent)
	}
	n := len(*sent)
	c.ProcessAck(1200, true)
	c.RunRecoveryRetransmit()
	if len(*sent) == n {
		t.Fatal("second partial ACK resent nothing: recovery must keep progressing")
	}
	for _, s := range (*sent)[n:] {
		for _, prev := range (*sent)[:n] {
			if s == prev {
				t.Fatalf("seq %d resent twice within one RTO", s)
			}
		}
	}
}

// Resends stay within the congestion window: segments resent earlier and
// still within the RTO count as in flight.
func TestTimeoutRecoveryResendRespectsCwnd(t *testing.T) {
	t.Parallel()
	c, sent := timeoutRecoveryConn(t, 10)
	c.CongWin = 300
	c.ProcessAck(1100, true)
	c.RunRecoveryRetransmit()
	first := len(*sent)
	if first == 0 || first*100 > 300+100 { // cwnd may grow by the acked 100 bytes
		t.Fatalf("first batch resent %d segments with cwnd 300-400", first)
	}
	// The next ACK frees one segment's worth; the earlier resends are still in
	// flight, so only about one more may go.
	c.ProcessAck(1200, true)
	c.RunRecoveryRetransmit()
	c.RetxMu.Lock()
	cwnd := c.CongWin
	inflight := 0
	for _, e := range c.Unacked {
		if !e.lastRetx.IsZero() && time.Since(e.lastRetx) < c.RTO {
			inflight += len(e.data)
		}
	}
	c.RetxMu.Unlock()
	if inflight > cwnd {
		t.Fatalf("%d bytes of resends in flight exceed cwnd %d", inflight, cwnd)
	}
}

// Data SACKed by the same packet as the partial ACK is not resent.
func TestTimeoutRecoveryResendSkipsSackedInSamePacket(t *testing.T) {
	t.Parallel()
	c, sent := timeoutRecoveryConn(t, 6)
	c.CongWin = 10 * MaxSegmentSize
	c.ProcessAck(1100, true)
	c.ProcessSACK([]SACKBlock{{Left: 1200, Right: 1400}}) // 1200 and 1300 arrived
	c.RunRecoveryRetransmit()
	for _, s := range *sent {
		if s == 1200 || s == 1300 {
			t.Fatalf("resent SACKed seq %d (sent %v)", s, *sent)
		}
	}
	if len(*sent) == 0 || (*sent)[0] != 1100 {
		t.Fatalf("resent %v, want the hole at 1100 first", *sent)
	}
}

// Fast recovery is untouched: a partial ACK there keeps the existing
// single-segment NewReno retransmit and schedules nothing.
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
	c.Unacked[0].attempts = 2 // no RTT sample (Karn)
	c.InRecovery, c.FastRecovery, c.RecoveryPoint = true, true, 1400
	c.CongWin, c.SSThresh = 8*MaxSegmentSize, 4*MaxSegmentSize
	c.RTO = 3 * time.Second
	c.ProcessAck(1100, true)
	c.RunRecoveryRetransmit()
	if c.RTO != 3*time.Second {
		t.Fatalf("RTO changed in fast recovery: %v", c.RTO)
	}
	if len(sent) != 1 || sent[0] != 1100 {
		t.Fatalf("fast-recovery partial ACK resent %v, want exactly [1100]", sent)
	}
}

// Resends are counted in Stats.Retransmits; new data sent after the timeout
// (at or beyond RecoveryPoint) counts as in flight; nothing is resent once
// recovery has ended.
func TestTimeoutRecoveryStatsNewDataAndExit(t *testing.T) {
	t.Parallel()
	c, sent := timeoutRecoveryConn(t, 6) // RecoveryPoint 1600
	// Two new-data segments sent after the timeout, still in flight.
	now := time.Now()
	c.Unacked = append(c.Unacked,
		&retxEntry{seq: 1600, data: make([]byte, 100), sentAt: now, origSentAt: now, attempts: 1},
		&retxEntry{seq: 1700, data: make([]byte, 100), sentAt: now, origSentAt: now, attempts: 1})
	c.CongWin = 300 // new data (200) leaves room for one resend after the ACK grows cwnd
	c.ProcessAck(1100, true)
	c.RunRecoveryRetransmit()
	if len(*sent) == 0 {
		t.Fatal("nothing resent")
	}
	c.Mu.Lock()
	retx := c.Stats.Retransmits
	c.Mu.Unlock()
	if retx != uint64(len(*sent)) {
		t.Fatalf("Stats.Retransmits = %d, want %d", retx, len(*sent))
	}
	if len(*sent)*100+200 > c.CongWin {
		t.Fatalf("resent %d segments with 200 bytes of new data in flight and cwnd %d", len(*sent), c.CongWin)
	}
	// Recovery ends: a later pending run must not resend anything.
	n := len(*sent)
	c.ProcessAck(1600, true) // ACK reaches RecoveryPoint
	c.RunRecoveryRetransmit()
	if len(*sent) != n {
		t.Fatalf("resent %v after recovery ended", (*sent)[n:])
	}
}

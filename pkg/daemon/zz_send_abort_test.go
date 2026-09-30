// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// When the send buffer stays full, sendDataBlocking gives up with
// ErrSendBufFull without appending the data, and abortConnection resets the
// stream with RST (not FIN) and removes it, so the stream cannot continue
// with a gap or look like a completed transfer.
func TestSendDataBlockingGivesUpAndAbortSendsRST(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)
	conn.NagleMu.Lock()
	conn.NagleBuf = make([]byte, MaxNagleBuf)
	conn.NagleMu.Unlock()

	start := time.Now()
	err := d.sendDataBlocking(conn, []byte("x"), 50*time.Millisecond)
	if !errors.Is(err, ErrSendBufFull) {
		t.Fatalf("sendDataBlocking err = %v, want ErrSendBufFull", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("sendDataBlocking took %v with maxWait 50ms", el)
	}
	conn.NagleMu.Lock()
	n := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if n != MaxNagleBuf {
		t.Fatalf("NagleBuf = %d bytes after a refused write, want %d (data must not be appended)", n, MaxNagleBuf)
	}

	d.abortConnection(conn, "test")
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65536)
	got, _, err := readFrameUDP(peer, buf)
	if err != nil {
		t.Fatalf("no packet after abort: %v", err)
	}
	pkt, err := protocol.Unmarshal(buf[4:got])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !pkt.HasFlag(protocol.FlagRST) || pkt.HasFlag(protocol.FlagFIN) {
		t.Fatalf("abort sent flags %#x, want RST without FIN", pkt.Flags)
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Fatalf("state after abort = %v, want CLOSED", st)
	}
	if d.ports.GetConnection(conn.ID) != nil {
		t.Fatal("aborted connection still registered")
	}
}

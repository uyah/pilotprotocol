// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"time"
)

// TestDriverBulkWriteIsNotDropped writes several MB through the driver while
// the receiver is not reading yet, so the sender's buffers must fill up. Driver writes reach the daemon as fire-and-forget IPC
// CmdSend; the daemon used to drop a write whenever the connection's send
// buffer was full (logging "IPC stream send failed"), so the stream silently
// lost data and the receiver never got the full byte count. Every byte must
// arrive, in order.
func TestDriverBulkWriteIsNotDropped(t *testing.T) {
	requireRealNetwork(t)
	env := NewTestEnv(t)
	infoA := env.AddDaemon()
	infoB := env.AddDaemon()

	ln, err := infoA.Driver.Listen(2300)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	const size = 4 << 20
	type result struct {
		n   int
		sum [32]byte
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{n: -1}
			return
		}
		defer conn.Close()
		// Hold off reading so the peer's receive window and the sender's
		// send buffer (2 MiB + 256 KiB) fill before anything drains.
		time.Sleep(3 * time.Second)
		h := sha256.New()
		n, _ := io.CopyN(h, conn, size)
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- result{n: int(n), sum: sum}
	}()

	conn, err := infoB.Driver.DialAddr(infoA.Daemon.Addr(), 2300)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	for off := 0; off < size; off += 64 << 10 {
		if _, err := conn.Write(data[off : off+64<<10]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
	}
	select {
	case r := <-done:
		if r.n != size {
			t.Fatalf("receiver got %d of %d bytes", r.n, size)
		}
		if !bytes.Equal(r.sum[:], want[:]) {
			t.Fatalf("receiver data differs from what was written")
		}
	case <-time.After(90 * time.Second):
		t.Fatalf("receiver did not get all %d bytes within 90 s (data dropped on the send path?)", size)
	}
}

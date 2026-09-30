// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestStreamThroughput measures one stream's bulk transfer rate between two
// daemons. Opt-in (PILOT_THROUGHPUT_MB=<size>): it is a measurement, not a
// pass/fail check. Run it on a path with added delay/loss (e.g. netem on lo)
// to compare segment-size and congestion settings.
func TestStreamThroughput(t *testing.T) {
	mb, _ := strconv.Atoi(os.Getenv("PILOT_THROUGHPUT_MB"))
	if mb <= 0 {
		t.Skip("set PILOT_THROUGHPUT_MB to run")
	}
	env := NewTestEnv(t)
	infoA := env.AddDaemon()
	infoB := env.AddDaemon()

	ln, err := infoA.Driver.Listen(2200)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	size := mb << 20
	done := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- -1
			return
		}
		defer conn.Close()
		buf := make([]byte, 65535)
		total := 0
		for total < size {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			total += n
		}
		done <- total
	}()

	// Send from inside daemon B (SendData with retry on ErrSendBufFull, as the
	// daemon's own net.Conn adapter does). The driver's Write is fire-and-forget
	// over IPC and silently drops data when the send buffer is full, so it
	// cannot drive a bulk transfer.
	conn, err := infoB.Daemon.DialConnection(infoA.Daemon.Addr(), 2200)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	chunk := make([]byte, 64<<10)
	if _, err := io.ReadFull(rand.Reader, chunk); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sendErr := make(chan error, 1)
	go func() {
		for sent := 0; sent < size; sent += len(chunk) {
			for {
				err := infoB.Daemon.SendData(conn, chunk)
				if err == nil {
					break
				}
				if !errors.Is(err, daemon.ErrSendBufFull) {
					sendErr <- err
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
	select {
	case got := <-done:
		el := time.Since(start)
		if got != size {
			t.Fatalf("received %d of %d bytes", got, size)
		}
		t.Logf("THROUGHPUT bytes=%d seconds=%.3f mbit_per_s=%.2f", size, el.Seconds(), float64(size)*8/el.Seconds()/1e6)
	case err := <-sendErr:
		t.Fatalf("send: %v", err)
	case <-time.After(10 * time.Minute):
		t.Fatalf("transfer of %d MB did not finish in 10 minutes", mb)
	}
}

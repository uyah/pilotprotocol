# Modifications in this fork

This is a modified version of Pilot Protocol (github.com/pilot-protocol/pilotprotocol), licensed under
AGPL-3.0-or-later like the original. Modifications by the Agent Network authors (d25-dev), 2026-09-30 to
2026-10-01, on top of upstream commit afc3e99, branch `anv/tunnel-frag`:

| file | change |
|---|---|
| pkg/daemon/fragment.go | added: PILF tunnel fragmentation (frames over 1223 bytes are split; per-source reassembly quotas, 3 s expiry) |
| pkg/daemon/tunnel.go | fragmented frame writing; reassembly on direct and relay paths |
| pkg/daemon/ipc.go | driver writes are never silently dropped: wait, or abort the stream with RST |
| pkg/daemon/services.go | sendDataBlocking with bounded back-off |
| pkg/daemon/daemon.go | abortConnection; close/abort teardown serialization; delayed-ACK guard; recovery retransmit after SACK processing |
| pkg/daemon/ports.go | abort state and teardown lock; retransmission of lost segments after a timeout, within cwnd |
| pkg/daemon/zz_*_test.go, tests/zz_*_test.go | added tests and benchmarks |

Frames that need more than one fragment do not interoperate with unmodified Pilot peers.
The full history is in the commit log (`git log afc3e99..`).

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// maxUnfragmentedUDPPayload is the largest UDP payload that fits the IPv6
// minimum MTU (1280 - 40 IPv6 header - 8 UDP header). A datagram within it
// needs no IP fragmentation on any path with an MTU of at least 1280.
const maxUnfragmentedUDPPayload = 1232

// relayHeaderLen is the beacon relay wrapping added by routing.WriteFrame:
// [0x05][senderNodeID(4)][destNodeID(4)].
const relayHeaderLen = 1 + 4 + 4

// TestSegmentDatagramFitsMinimumMTU builds the largest datagram a data
// segment can produce — a full MaxSegmentSize payload, marshaled, sealed as a
// secure tunnel frame and wrapped for beacon relay — and requires it to fit
// without IP fragmentation. With 4096-byte segments every full segment became
// a ~4.2 KB datagram; on paths that drop IP fragments (VPNs, CGNATs, mobile
// networks) those never arrived, and retransmitting the same segment could
// not recover, so any message larger than about one MTU stalled for good.
func TestSegmentDatagramFitsMinimumMTU(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xDEADBEEF)
	peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 1, Node: 1},
		Dst:      protocol.Addr{Network: 1, Node: 2},
		SrcPort:  49152,
		DstPort:  1001,
		Seq:      1,
		Ack:      1,
		Window:   RecvBufSize,
		Payload:  make([]byte, MaxSegmentSize),
	}
	plain, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	frame := tm.encryptFrame(pc, plain)
	if got := len(frame) + relayHeaderLen; got > maxUnfragmentedUDPPayload {
		t.Fatalf("relayed datagram for a full segment is %d bytes (segment %d + packet header %d + tunnel framing %d + relay %d), want <= %d",
			got, MaxSegmentSize, len(plain)-MaxSegmentSize, len(frame)-len(plain), relayHeaderLen, maxUnfragmentedUDPPayload)
	}
}

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssociationShutdownUnblocksPendingWrites covers blocked writers waiting
// on writeNotify when the shutdown is initiated locally or by the peer.
func TestAssociationShutdownUnblocksPendingWrites(t *testing.T) {
	for name, transition := range map[string]func(*Association) error{
		"local shutdown": func(assoc *Association) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			return assoc.Shutdown(ctx)
		},
		"peer shutdown": func(assoc *Association) error {
			assoc.lock.Lock()
			defer assoc.lock.Unlock()

			return assoc.handleShutdown(&chunkShutdown{cumulativeTSNAck: 99})
		},
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{BlockWrite: true})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(established)
			assoc.cumulativeTSNAckPoint = 99
			assoc.advancedPeerTSNAckPoint = 99
			assoc.writePending = true
			writeNotify := assoc.writeNotify

			err := transition(assoc)
			if name == "local shutdown" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.NoError(t, err)
			}
			assert.NotEqual(t, established, assoc.getState())
			assert.False(t, assoc.writePending)

			select {
			case <-writeNotify:
			default:
				assert.Fail(t, "blocked writers were not notified of shutdown")
			}
		})
	}
}

// TestAssociationInvalidShutdownAckDoesNotChangeState runs for the established
// and shutdown-pending entry states: a malformed cumulative TSN ACK must roll
// back every observable state change, including blocked writer notification.
func TestAssociationInvalidShutdownAckDoesNotChangeState(t *testing.T) {
	for name, state := range map[string]uint32{
		"established":      established,
		"shutdown pending": shutdownPending,
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{BlockWrite: state == established})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(state)
			assoc.cumulativeTSNAckPoint = 99
			assoc.inflightQueue.pushNoCheck(mkChunk(100, time.Now()))
			var writeNotify chan struct{}
			if state == established {
				assoc.writePending = true
				writeNotify = assoc.writeNotify
			}

			assoc.lock.Lock()
			err := assoc.handleShutdown(&chunkShutdown{cumulativeTSNAck: 101})
			assoc.lock.Unlock()

			require.ErrorIs(t, err, ErrInflightQueueTSNPop)
			assert.Equal(t, state, assoc.getState())
			assert.Equal(t, uint32(99), assoc.cumulativeTSNAckPoint)
			assert.Equal(t, 1, assoc.inflightQueue.size())
			assert.False(t, assoc.willSendShutdownAck)
			if state == established {
				assert.True(t, assoc.writePending)
				select {
				case <-writeNotify:
					assert.Fail(t, "invalid shutdown notified blocked writers")
				default:
				}
			}
		})
	}
}

// TestAssociationCrossedShutdownClearsPendingShutdown verifies that a SHUTDOWN
// arriving in SHUTDOWN-SENT replaces the pending SHUTDOWN with a single
// SHUTDOWN ACK and no duplicate response is ever produced.
func TestAssociationCrossedShutdownClearsPendingShutdown(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.cumulativeTSNAckPoint = 99
	assoc.setState(shutdownSent)
	assoc.willSendShutdown = true
	require.True(t, assoc.t2Shutdown.start(1000))

	assoc.lock.Lock()
	err := assoc.handleShutdown(&chunkShutdown{cumulativeTSNAck: 99})
	assoc.lock.Unlock()

	require.NoError(t, err)
	assert.Equal(t, shutdownAckSent, assoc.getState())
	assert.False(t, assoc.willSendShutdown)
	assert.True(t, assoc.willSendShutdownAck)
	assert.False(t, assoc.t2Shutdown.isRunning())

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)
	assert.True(t, assoc.t2Shutdown.isRunning())

	packet := &packet{}
	require.NoError(t, packet.unmarshal(false, rawPackets[0]))
	require.Len(t, packet.chunks, 1)
	require.IsType(t, &chunkShutdownAck{}, packet.chunks[0])
	assert.False(t, assoc.willSendShutdown)
	assert.False(t, assoc.willSendShutdownAck)

	rawPackets, ok = assoc.gatherOutbound()
	assert.True(t, ok)
	assert.Empty(t, rawPackets)
}

// TestAssociationRepeatedShutdownRetransmitsAck covers the duplicate-response
// case in SHUTDOWN-ACK-SENT: retransmitted SHUTDOWN chunks keep getting a
// SHUTDOWN ACK instead of being silently dropped.
func TestAssociationRepeatedShutdownRetransmitsAck(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.setState(shutdownAckSent)
	require.True(t, assoc.t2Shutdown.start(1000))

	assoc.lock.Lock()
	err := assoc.handleShutdown(&chunkShutdown{})
	assoc.lock.Unlock()

	require.NoError(t, err)
	assert.Equal(t, shutdownAckSent, assoc.getState())
	assert.True(t, assoc.willSendShutdownAck)
	assert.False(t, assoc.t2Shutdown.isRunning())

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)
	assert.True(t, assoc.t2Shutdown.isRunning())

	pkt := &packet{}
	require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
	require.Len(t, pkt.chunks, 1)
	require.IsType(t, &chunkShutdownAck{}, pkt.chunks[0])
}

// TestAssociationShutdownAckPrioritizedOverControlQueue ensures a SHUTDOWN ACK
// is not queued behind unrelated control traffic.
func TestAssociationShutdownAckPrioritizedOverControlQueue(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.setState(shutdownAckSent)
	assoc.willSendShutdownAck = true
	assoc.controlQueue.push(assoc.createPacket([]chunk{&chunkCookieAck{}}))

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 2)
	assert.True(t, assoc.t2Shutdown.isRunning())

	shutdownAckPacket := &packet{}
	require.NoError(t, shutdownAckPacket.unmarshal(false, rawPackets[0]))
	require.Len(t, shutdownAckPacket.chunks, 1)
	require.IsType(t, &chunkShutdownAck{}, shutdownAckPacket.chunks[0])

	controlPacket := &packet{}
	require.NoError(t, controlPacket.unmarshal(false, rawPackets[1]))
	require.Len(t, controlPacket.chunks, 1)
	require.IsType(t, &chunkCookieAck{}, controlPacket.chunks[0])
}

// TestAssociationShutdownPrioritizedOverControlQueue ensures the SHUTDOWN (and
// its immediate SACK) jump queued control traffic.
func TestAssociationShutdownPrioritizedOverControlQueue(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.payloadQueue.init(0)
	assoc.setState(shutdownSent)
	assoc.willSendShutdown = true
	assoc.ackState = ackStateImmediate
	assoc.controlQueue.push(assoc.createPacket([]chunk{&chunkCookieAck{}}))

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 3)
	assert.True(t, assoc.t2Shutdown.isRunning())

	expected := []chunk{
		&chunkSelectiveAck{},
		&chunkShutdown{},
		&chunkCookieAck{},
	}
	for i, expectedChunk := range expected {
		packet := &packet{}
		require.NoError(t, packet.unmarshal(false, rawPackets[i]))
		require.Len(t, packet.chunks, 1)
		require.IsType(t, expectedChunk, packet.chunks[0])
	}
}

// TestAssociationShutdownAckClearsPendingShutdownResponses verifies that once
// SHUTDOWN ACK has been received, neither stale SHUTDOWN nor SHUTDOWN ACK
// flags can produce extra packets alongside SHUTDOWN COMPLETE.
func TestAssociationShutdownAckClearsPendingShutdownResponses(t *testing.T) {
	for name, test := range map[string]struct {
		state               uint32
		willSendShutdown    bool
		willSendShutdownAck bool
	}{
		"shutdown sent": {
			state:            shutdownSent,
			willSendShutdown: true,
		},
		"shutdown ack sent": {
			state:               shutdownAckSent,
			willSendShutdownAck: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(test.state)
			assoc.willSendShutdown = test.willSendShutdown
			assoc.willSendShutdownAck = test.willSendShutdownAck

			assoc.lock.Lock()
			assoc.handleShutdownAck(&chunkShutdownAck{})
			assoc.lock.Unlock()

			assert.False(t, assoc.willSendShutdown)
			assert.False(t, assoc.willSendShutdownAck)
			assert.True(t, assoc.willSendShutdownComplete)

			assoc.willSendShutdown = true
			assoc.willSendShutdownAck = true

			rawPackets, ok := assoc.gatherOutbound()
			require.False(t, ok)
			require.Len(t, rawPackets, 1)

			packet := &packet{}
			require.NoError(t, packet.unmarshal(false, rawPackets[0]))
			require.Len(t, packet.chunks, 1)
			require.IsType(t, &chunkShutdownComplete{}, packet.chunks[0])
		})
	}
}

// TestAssociationShutdownCompleteWinsOverLateData covers DATA chunks arriving
// after SHUTDOWN ACK: they must not restart the connection or delay SHUTDOWN
// COMPLETE.
func TestAssociationShutdownCompleteWinsOverLateData(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.payloadQueue.init(0)
	assoc.setState(shutdownSent)

	assoc.lock.Lock()
	assoc.handleShutdownAck(&chunkShutdownAck{})
	packets := assoc.handleData(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		tsn:               0,
		streamIdentifier:  1,
		payloadType:       PayloadTypeWebRTCBinary,
		userData:          []byte("late duplicate"),
	})
	assoc.lock.Unlock()

	require.Nil(t, packets)
	assoc.handleChunksEnd()

	assert.True(t, assoc.willSendShutdownComplete)
	assert.False(t, assoc.willSendShutdown)
	assert.False(t, assoc.immediateAckTriggered)
	assert.Zero(t, assoc.stats.getNumDATAs())

	rawPackets, ok := assoc.gatherOutbound()
	require.False(t, ok)
	require.Len(t, rawPackets, 1)

	packet := &packet{}
	require.NoError(t, packet.unmarshal(false, rawPackets[0]))
	require.Len(t, packet.chunks, 1)
	require.IsType(t, &chunkShutdownComplete{}, packet.chunks[0])
	assert.False(t, assoc.willSendShutdownComplete)
	assert.True(t, assoc.shutdownCompletePending)
	assert.False(t, assoc.t2Shutdown.isRunning())

	assoc.lock.Lock()
	packets = assoc.handleData(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		tsn:               0,
		streamIdentifier:  1,
		payloadType:       PayloadTypeWebRTCBinary,
		userData:          []byte("late after gather"),
	})
	assoc.lock.Unlock()

	assert.Nil(t, packets)
	assert.False(t, assoc.willSendShutdown)
	assert.Zero(t, assoc.stats.getNumDATAs())
}

// TestAssociationShutdownCompleteWinsOverLateT2Timeout covers T2 timer events
// firing after SHUTDOWN ACK has already been processed.
func TestAssociationShutdownCompleteWinsOverLateT2Timeout(t *testing.T) {
	for name, state := range map[string]uint32{
		"shutdown sent":     shutdownSent,
		"shutdown ack sent": shutdownAckSent,
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(state)
			require.True(t, assoc.t2Shutdown.start(1000))

			assoc.lock.Lock()
			assoc.handleShutdownAck(&chunkShutdownAck{})
			assoc.lock.Unlock()

			assoc.onRetransmissionTimeout(timerT2Shutdown, 1)

			assert.True(t, assoc.willSendShutdownComplete)
			assert.False(t, assoc.willSendShutdown)
			assert.False(t, assoc.willSendShutdownAck)
			assert.False(t, assoc.t2Shutdown.isRunning())

			rawPackets, ok := assoc.gatherOutbound()
			require.False(t, ok)
			require.Len(t, rawPackets, 1)

			packet := &packet{}
			require.NoError(t, packet.unmarshal(false, rawPackets[0]))
			require.Len(t, packet.chunks, 1)
			require.IsType(t, &chunkShutdownComplete{}, packet.chunks[0])

			assoc.onRetransmissionTimeout(timerT2Shutdown, 2)
			assert.False(t, assoc.willSendShutdown)
			assert.False(t, assoc.willSendShutdownAck)
		})
	}
}

// TestAssociationShutdownDrainsPendingData verifies DATA accepted before a
// local shutdown is transmitted before the SHUTDOWN chunk.
func TestAssociationShutdownDrainsPendingData(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.setState(established)
	assoc.initialTSN = 100
	assoc.myNextTSN = 100
	assoc.cumulativeTSNAckPoint = 99
	assoc.advancedPeerTSNAckPoint = 99
	assoc.setRWND(1024)

	assoc.pendingQueue.push(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		streamIdentifier:  1,
		payloadType:       PayloadTypeWebRTCBinary,
		userData:          []byte("queued before shutdown"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, assoc.Shutdown(ctx), context.Canceled)
	assert.Equal(t, shutdownPending, assoc.getState())
	assert.False(t, assoc.willSendShutdown)

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)

	pkt := &packet{}
	require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
	require.Len(t, pkt.chunks, 1)
	data, ok := pkt.chunks[0].(*chunkPayloadData)
	require.True(t, ok)
	assert.Equal(t, uint32(100), data.tsn)
	assert.Zero(t, assoc.pendingQueue.size())
	assert.Equal(t, 1, assoc.inflightQueue.size())
	assert.Equal(t, shutdownPending, assoc.getState())

	assoc.lock.Lock()
	err := assoc.handleSack(&chunkSelectiveAck{
		cumulativeTSNAck:               100,
		advertisedReceiverWindowCredit: 1024,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	assert.Equal(t, shutdownSent, assoc.getState())
	assert.True(t, assoc.willSendShutdown)

	rawPackets, ok = assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)

	pkt = &packet{}
	require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
	require.Len(t, pkt.chunks, 1)
	require.IsType(t, &chunkShutdown{}, pkt.chunks[0])
}

// TestAssociationCrossedShutdownDrainsPendingData verifies DATA accepted before
// the peer's SHUTDOWN is still transmitted before the SHUTDOWN ACK.
func TestAssociationCrossedShutdownDrainsPendingData(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() { _ = assoc.close() })
	assoc.setState(shutdownPending)
	assoc.initialTSN = 100
	assoc.myNextTSN = 100
	assoc.cumulativeTSNAckPoint = 99
	assoc.advancedPeerTSNAckPoint = 99
	assoc.setRWND(1024)

	assoc.pendingQueue.push(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		streamIdentifier:  1,
		payloadType:       PayloadTypeWebRTCBinary,
		userData:          []byte("queued before crossed shutdown"),
	})

	assoc.lock.Lock()
	err := assoc.handleShutdown(&chunkShutdown{cumulativeTSNAck: 99})
	assoc.lock.Unlock()
	require.NoError(t, err)
	assert.Equal(t, shutdownReceived, assoc.getState())
	assert.False(t, assoc.willSendShutdown)
	assert.False(t, assoc.willSendShutdownAck)

	rawPackets, ok := assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)

	pkt := &packet{}
	require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
	require.Len(t, pkt.chunks, 1)
	data, ok := pkt.chunks[0].(*chunkPayloadData)
	require.True(t, ok)
	assert.Equal(t, uint32(100), data.tsn)
	assert.Zero(t, assoc.pendingQueue.size())
	assert.Equal(t, 1, assoc.inflightQueue.size())

	assoc.lock.Lock()
	err = assoc.handleSack(&chunkSelectiveAck{
		cumulativeTSNAck:               100,
		advertisedReceiverWindowCredit: 1024,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	assert.Equal(t, shutdownAckSent, assoc.getState())
	assert.True(t, assoc.willSendShutdownAck)

	rawPackets, ok = assoc.gatherOutbound()
	require.True(t, ok)
	require.Len(t, rawPackets, 1)

	pkt = &packet{}
	require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
	require.Len(t, pkt.chunks, 1)
	require.IsType(t, &chunkShutdownAck{}, pkt.chunks[0])
}

// TestAssociationSendsForwardTSNWhileDrainingShutdown ensures partial
// reliability bookkeeping still emits FORWARD TSN while shutdown drains.
func TestAssociationSendsForwardTSNWhileDrainingShutdown(t *testing.T) {
	for name, state := range map[string]uint32{
		"shutdown pending":  shutdownPending,
		"shutdown received": shutdownReceived,
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(state)
			assoc.useForwardTSN = true
			assoc.cumulativeTSNAckPoint = 9
			assoc.advancedPeerTSNAckPoint = 9
			assoc.inflightQueue.pushNoCheck(&chunkPayloadData{
				beginningFragment:    true,
				endingFragment:       true,
				tsn:                  10,
				streamIdentifier:     1,
				streamSequenceNumber: 2,
				userData:             []byte("abandoned"),
				nSent:                1,
				_abandoned:           true,
				_allInflight:         true,
			})

			assoc.lock.Lock()
			err := assoc.finishAcknowledgement(
				&chunkSelectiveAck{cumulativeTSNAck: 9},
				acknowledgementResult{htna: 9},
			)
			assoc.lock.Unlock()
			require.NoError(t, err)
			require.Equal(t, uint32(10), assoc.advancedPeerTSNAckPoint)
			require.True(t, assoc.willSendForwardTSN)

			rawPackets, ok := assoc.gatherOutbound()
			require.True(t, ok)
			require.Len(t, rawPackets, 1)

			pkt := &packet{}
			require.NoError(t, pkt.unmarshal(false, rawPackets[0]))
			require.Len(t, pkt.chunks, 1)
			forwardTSN, ok := pkt.chunks[0].(*chunkForwardTSN)
			require.True(t, ok)
			assert.Equal(t, uint32(10), forwardTSN.newCumulativeTSN)
			assert.False(t, assoc.willSendForwardTSN)
		})
	}
}

// TestAssociationShutdownAdvancesAfterPendingStreamReset covers a zero-length
// DATA pending in the queue: its RECONFIG must be sent together with the
// shutdown response without stranding the association, and timer-driven
// retransmissions keep the same ordering.
func TestAssociationShutdownAdvancesAfterPendingStreamReset(t *testing.T) {
	for name, test := range map[string]struct {
		state         uint32
		expectedState uint32
		expectedChunk chunk
	}{
		"shutdown pending": {
			state:         shutdownPending,
			expectedState: shutdownSent,
			expectedChunk: &chunkShutdown{},
		},
		"shutdown received": {
			state:         shutdownReceived,
			expectedState: shutdownAckSent,
			expectedChunk: &chunkShutdownAck{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{})
			t.Cleanup(func() { _ = assoc.close() })
			assoc.setState(test.state)
			assoc.myNextTSN = 100

			assoc.pendingQueue.push(&chunkPayloadData{
				beginningFragment: true,
				endingFragment:    true,
				streamIdentifier:  1,
			})

			rawPackets, ok := assoc.gatherOutbound()
			require.True(t, ok)
			require.Len(t, rawPackets, 2)
			assert.Equal(t, test.expectedState, assoc.getState())
			assert.Zero(t, assoc.pendingQueue.size())
			assert.Zero(t, assoc.inflightQueue.size())

			reconfigPacket := &packet{}
			require.NoError(t, reconfigPacket.unmarshal(false, rawPackets[0]))
			require.Len(t, reconfigPacket.chunks, 1)
			require.IsType(t, &chunkReconfig{}, reconfigPacket.chunks[0])

			shutdownPacket := &packet{}
			require.NoError(t, shutdownPacket.unmarshal(false, rawPackets[1]))
			require.Len(t, shutdownPacket.chunks, 1)
			require.IsType(t, test.expectedChunk, shutdownPacket.chunks[0])

			assoc.onRetransmissionTimeout(timerReconfig, 1)
			assoc.onRetransmissionTimeout(timerT2Shutdown, 1)
			require.True(t, assoc.willRetransmitReconfig)

			rawPackets, ok = assoc.gatherOutbound()
			require.True(t, ok)
			require.Len(t, rawPackets, 2)
			assert.Equal(t, test.expectedState, assoc.getState())
			assert.False(t, assoc.willRetransmitReconfig)

			retransmittedShutdown := &packet{}
			require.NoError(t, retransmittedShutdown.unmarshal(false, rawPackets[0]))
			require.Len(t, retransmittedShutdown.chunks, 1)
			require.IsType(t, test.expectedChunk, retransmittedShutdown.chunks[0])

			retransmitted := &packet{}
			require.NoError(t, retransmitted.unmarshal(false, rawPackets[1]))
			require.Len(t, retransmitted.chunks, 1)
			require.IsType(t, &chunkReconfig{}, retransmitted.chunks[0])
		})
	}
}

// pumpBridge drives queued packets through the bridge until both queues are
// empty and the associations go idle.
func pumpBridge(t *testing.T, br *test.Bridge, deadline time.Time) {
	t.Helper()
	idleTicks := 0
	for time.Now().Before(deadline) {
		n := br.Tick()
		if n == 0 && br.Len(0) == 0 && br.Len(1) == 0 {
			idleTicks++
			// Keep pumping long enough to survive a full initial RTO (1s) of
			// timer-driven retransmission before declaring the bridge idle.
			if idleTicks >= 220 {
				return
			}
		} else {
			idleTicks = 0
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("bridge did not drain in time (queues: %d/%d)", br.Len(0), br.Len(1))
}

func waitClosed(t *testing.T, a *Association, deadline time.Time) {
	t.Helper()
	for time.Now().Before(deadline) {
		select {
		case <-a.readLoopCloseCh:
			return
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("association %s did not close", a.name)
}

// TestAssociationE2ESimultaneousShutdown drives both endpoints into shutdown
// at the same time while DATA is flowing. Both sides must reach the closed
// terminal state and every delivered message must arrive in order.
func TestAssociationE2ESimultaneousShutdown(t *testing.T) {
	checkGoroutineLeaks(t)

	br := test.NewBridge()
	a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
	require.NoError(t, err)
	defer closeAssociationPair(br, a0, a1)

	s0, s1, err := establishSessionPair(br, a0, a1, 1)
	require.NoError(t, err)

	const messages = 20
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1024)
		for i := 0; i < messages; i++ {
			n, _, readErr := s1.ReadSCTP(buf)
			if readErr != nil {
				return
			}
			assert.Equal(t, 1, n)
			assert.Equal(t, byte(i), buf[0])
		}
	}()

	for i := 0; i < messages; i++ {
		_, err = s0.WriteSCTP([]byte{byte(i)}, PayloadTypeWebRTCBinary)
		require.NoError(t, err)
		if i%5 == 0 {
			pumpBridge(t, br, time.Now().Add(2*time.Second))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownErrs := make(chan error, 2)
	go func() { shutdownErrs <- a0.Shutdown(ctx) }()
	go func() { shutdownErrs <- a1.Shutdown(ctx) }()

	pumpBridge(t, br, time.Now().Add(4*time.Second))

	for i := 0; i < 2; i++ {
		assert.NoError(t, <-shutdownErrs)
	}
	waitClosed(t, a0, time.Now().Add(2*time.Second))
	waitClosed(t, a1, time.Now().Add(2*time.Second))
	assert.Equal(t, closed, a0.getState())
	assert.Equal(t, closed, a1.getState())

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		assert.Fail(t, "reader did not finish draining accepted DATA")
	}
}

// TestAssociationE2ESimultaneousShutdownWithQueuedData starts both shutdowns
// while user DATA is still queued locally. The accepted data must be
// transmitted in order before either side sends its terminal control chunk.
func TestAssociationE2ESimultaneousShutdownWithQueuedData(t *testing.T) {
	checkGoroutineLeaks(t)

	br := test.NewBridge()
	a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
	require.NoError(t, err)
	defer closeAssociationPair(br, a0, a1)

	s0, s1, err := establishSessionPair(br, a0, a1, 1)
	require.NoError(t, err)

	const messages = 10
	for i := 0; i < messages; i++ {
		_, err = s0.WriteSCTP([]byte{byte(i)}, PayloadTypeWebRTCBinary)
		require.NoError(t, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownErrs := make(chan error, 2)
	go func() { shutdownErrs <- a0.Shutdown(ctx) }()
	go func() { shutdownErrs <- a1.Shutdown(ctx) }()

	received := make(chan byte, messages)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1024)
		for {
			n, _, readErr := s1.ReadSCTP(buf)
			if readErr != nil {
				return
			}
			for _, b := range buf[:n] {
				select {
				case received <- b:
				default:
				}
			}
		}
	}()

	pumpBridge(t, br, time.Now().Add(4*time.Second))

	for i := 0; i < 2; i++ {
		assert.NoError(t, <-shutdownErrs)
	}
	waitClosed(t, a0, time.Now().Add(2*time.Second))
	waitClosed(t, a1, time.Now().Add(2*time.Second))
	assert.Equal(t, closed, a0.getState())
	assert.Equal(t, closed, a1.getState())

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		assert.Fail(t, "reader did not stop after close")
	}

	close(received)
	got := make([]byte, 0, messages)
	for b := range received {
		got = append(got, b)
	}
	require.Len(t, got, messages, "all DATA accepted before shutdown must be delivered")
	for i, b := range got {
		assert.Equal(t, byte(i), b)
	}
}

// packetHasChunkType reports whether a raw SCTP packet carries a chunk of the
// given type (the chunk type is the first byte after the 12-byte header).
func packetHasChunkType(raw []byte, want chunkType) bool {
	off := int(commonHeaderSize)
	for off+1 <= len(raw) {
		if chunkType(raw[off]) == want {
			return true
		}
		if off+4 > len(raw) {
			return false
		}
		chunkLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		if chunkLen < 4 {
			return false
		}
		off += chunkLen
	}

	return false
}

// TestAssociationE2EShutdownIgnoresLatePackets verifies that late packets and
// timer retransmissions during the shutdown handshake cannot move an endpoint
// out of the correct terminal state, and both sides close cleanly.
func TestAssociationE2EShutdownIgnoresLatePackets(t *testing.T) {
	checkGoroutineLeaks(t)

	br := test.NewBridge()
	a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
	require.NoError(t, err)
	defer closeAssociationPair(br, a0, a1)

	s0, s1, err := establishSessionPair(br, a0, a1, 1)
	require.NoError(t, err)

	// Send one message and make sure it has been delivered before shutdown.
	_, err = s0.WriteSCTP([]byte{0x42}, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	pumpBridge(t, br, time.Now().Add(2*time.Second))

	buf := make([]byte, 1024)
	n, _, err := s1.ReadSCTP(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- a0.Shutdown(ctx) }()

	// Drive the handshake. Late chunks and timer-driven retransmissions must
	// never restart either endpoint or strand it away from the terminal state.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		br.Tick()
		select {
		case shutdownErr := <-shutdownDone:
			require.NoError(t, shutdownErr)
			// Drain the peer's terminal SHUTDOWN COMPLETE response.
			pumpBridge(t, br, time.Now().Add(2*time.Second))
			goto shutdownFinished
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a0 shutdown did not complete")

shutdownFinished:
	waitClosed(t, a0, time.Now().Add(2*time.Second))
	waitClosed(t, a1, time.Now().Add(2*time.Second))
	assert.Equal(t, closed, a0.getState())
	assert.Equal(t, closed, a1.getState())

	// Both bridge conns are closing now; further writes are refused and stale
	// traffic can never reach an exited read loop. The states stay terminal.
	_, err = br.GetConn0().Write([]byte{0, 0, 0, 0})
	assert.Error(t, err)
	_, err = br.GetConn1().Write([]byte{0, 0, 0, 0})
	assert.Error(t, err)
	br.Tick()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, closed, a0.getState())
	assert.Equal(t, closed, a1.getState())
}

// TestAssociationE2EShutdownSurvivesPacketLoss drops the first SHUTDOWN chunk
// so the T2 timer must retransmit it. Both endpoints still have to reach the
// closed terminal state without a restart.
func TestAssociationE2EShutdownSurvivesPacketLoss(t *testing.T) {
	checkGoroutineLeaks(t)

	br := test.NewBridge()
	a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
	require.NoError(t, err)
	defer closeAssociationPair(br, a0, a1)

	_, _, err = establishSessionPair(br, a0, a1, 1)
	require.NoError(t, err)

	var droppedShutdown atomic.Bool
	// a0 is conn0: its SHUTDOWN travels from id 0 to id 1.
	br.Filter(0, func(raw []byte) bool {
		if !droppedShutdown.Load() && packetHasChunkType(raw, ctShutdown) {
			droppedShutdown.Store(true)

			return false
		}

		return true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- a0.Shutdown(ctx) }()

	pumpBridge(t, br, time.Now().Add(9*time.Second))

	require.NoError(t, <-shutdownDone)
	assert.True(t, droppedShutdown.Load(), "the first SHUTDOWN should have been dropped")
	waitClosed(t, a0, time.Now().Add(2*time.Second))
	waitClosed(t, a1, time.Now().Add(2*time.Second))
	assert.Equal(t, closed, a0.getState())
	assert.Equal(t, closed, a1.getState())
}

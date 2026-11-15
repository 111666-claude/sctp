package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssociation_DuplicateShutdownChunks verifies that retransmitted and
// duplicated shutdown control chunks are handled idempotently: they never
// error, never move the state machine backwards, and always keep the
// appropriate response armed so the peer cannot be left hanging.
func TestAssociation_DuplicateShutdownChunks(t *testing.T) {
	a1, a2 := createAssocs(t)
	defer func() {
		_ = a1.Close()
		_ = a2.Close()
	}()

	// --- Receiver side: a burst of duplicated SHUTDOWN chunks ---
	a2.lock.Lock()
	for i := 0; i < 3; i++ {
		a2.handleShutdown(&chunkShutdown{})
		require.Contains(t, []uint32{shutdownReceived, shutdownAckSent}, a2.getState())
	}
	require.Equal(t, shutdownAckSent, a2.getState(), "receiver must settle in shutdownAckSent")
	assert.True(t, a2.willSendShutdownAck, "SHUTDOWN-ACK must be armed")

	// Another duplicate SHUTDOWN while in shutdownAckSent keeps the state
	// stable and re-arms the acknowledgement so a lost ACK is recovered.
	a2.handleShutdown(&chunkShutdown{})
	assert.Equal(t, shutdownAckSent, a2.getState())
	assert.True(t, a2.willSendShutdownAck)

	// A SHUTDOWN-ACK in this state is simply ignored (no panic, no state
	// change) — it is only meaningful to the shutdown initiator.
	a2.handleShutdownAck(&chunkShutdownAck{})
	assert.Equal(t, shutdownAckSent, a2.getState())
	a2.lock.Unlock()

	// --- Initiator side: unexpected / duplicated control chunks ---
	a1.lock.Lock()
	established := a1.getState()

	// An unexpected SHUTDOWN-COMPLETE while not in shutdownAckSent must be
	// silently tolerated and must not move the state.
	require.NoError(t, a1.handleShutdownComplete(&chunkShutdownComplete{}))
	assert.Equal(t, established, a1.getState())

	// Drive the initiator into shutdownSent as Shutdown() would.
	a1.setState(shutdownSent)
	a1.willSendShutdown = true

	// A duplicate SHUTDOWN-ACK stops the retransmit timer and (re)arms
	// SHUTDOWN-COMPLETE; a second one must not break anything.
	a1.handleShutdownAck(&chunkShutdownAck{})
	assert.True(t, a1.willSendShutdownComplete)
	a1.handleShutdownAck(&chunkShutdownAck{})
	assert.True(t, a1.willSendShutdownComplete)
	a1.lock.Unlock()
}

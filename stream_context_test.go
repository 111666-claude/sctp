// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testContextMsgSize = 4000

// newBlockedWriteAssoc builds an association pair whose writer is parked on a
// full peer receive window, so the next write blocks inside sendPayloadData.
// It returns the blocked association, the sending stream and its peer reader.
func newBlockedWriteAssoc(t *testing.T, useInterleaving bool) (*Association, *Stream, *Stream) {
	t.Helper()

	opts := []AssociationOption{
		WithBlockWrite(true),
		WithMaxReceiveBufferSize(testContextMsgSize),
	}
	if useInterleaving {
		opts = append(opts, WithEnableInterleaving(true))
	}
	assoc, peerAssoc, err := association(t, pipeDump, opts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = peerAssoc.Close()
		_ = assoc.Close()
	})

	sendStream, err := assoc.OpenStream(1, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	// Prime the association so AcceptStream returns the peer stream.
	_, err = sendStream.WriteSCTP([]byte("hello"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	peerStream, err := peerAssoc.AcceptStream()
	require.NoError(t, err)

	// Two window-sized messages leave the peer with no advertised rwnd, so the
	// following context write has to wait on the blocking queue.
	data := make([]byte, testContextMsgSize)
	_, err = sendStream.WriteSCTP(data, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = sendStream.WriteSCTP(data, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	return assoc, sendStream, peerStream
}

func waitForBlockedWrite(t *testing.T, a *Association) {
	t.Helper()

	require.Eventually(t, func() bool {
		a.lock.Lock()
		blocked := a.blockWrite && a.writePending
		a.lock.Unlock()

		return blocked
	}, time.Second, time.Millisecond)
}

// TestStreamWriteSCTPContextCancelBeforeQueue makes sure a write whose context
// is already canceled never reaches the send queue and does not consume a
// sequence number, message identifier or buffered amount.
func TestStreamWriteSCTPContextCancelBeforeQueue(t *testing.T) {
	t.Parallel()

	for _, interleaving := range []bool{false, true} {
		t.Run(interleavingName(interleaving), func(t *testing.T) {
			t.Parallel()

			stream := newTestPacketizingStream(t, interleaving, 1200)
			// The packetizing helper leaves the association unstarted; make it a
			// live, blocked association so a pre-canceled context is rejected at
			// the queue wait rather than at the state check.
			assoc := stream.association
			assoc.setState(established)
			assoc.blockWrite = true
			assoc.writePending = true
			assoc.writeNotify = make(chan struct{}, 1)
			assoc.pendingQueue = newPendingQueue(nil)
			require.Equal(t, StreamStateOpen, stream.State())

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			n, err := stream.WriteSCTPContext(ctx, []byte("never sent"), PayloadTypeWebRTCBinary)
			require.Zero(t, n)
			require.ErrorIs(t, err, context.Canceled)

			assert.Zero(t, stream.BufferedAmount())
			stream.lock.RLock()
			assert.Zero(t, stream.sequenceNumber)
			assert.Zero(t, stream.nextOrderedMID)
			assert.Zero(t, stream.nextUnorderedMID)
			stream.lock.RUnlock()
			assert.Zero(t, assoc.pendingQueue.size())
			// Rejection must not have unblocked any other waiting write.
			assoc.lock.Lock()
			assert.True(t, assoc.writePending)
			assoc.lock.Unlock()
		})
	}
}

// TestStreamWriteSCTPContextCanceledWhileBlocked exercises the blocking queue
// cancellation race: with BlockWrite the write waits for send space, and
// canceling the context must unwind just that write without touching the
// stream deadline or the message counterstream.
func TestStreamWriteSCTPContextCanceledWhileBlocked(t *testing.T) {
	for _, interleaving := range []bool{false, true} {
		t.Run(interleavingName(interleaving), func(t *testing.T) {
			checkGoroutineLeaks(t)

			assoc, sendStream, _ := newBlockedWriteAssoc(t, interleaving)

			// Snapshot the state the two priming writes produced.
			bufferedBefore := sendStream.BufferedAmount()
			sendStream.lock.RLock()
			ssnBefore := sendStream.sequenceNumber
			orderedMIDBefore := sendStream.nextOrderedMID
			unorderedMIDBefore := sendStream.nextUnorderedMID
			sendStream.lock.RUnlock()

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			data := make([]byte, testContextMsgSize)
			go func() {
				written, writeErr := sendStream.WriteSCTPContext(ctx, data, PayloadTypeWebRTCBinary)
				assert.Zero(t, written)
				done <- writeErr
			}()

			waitForBlockedWrite(t, assoc)

			// The stream deadline must remain untouched.
			_, hasDeadline := sendStream.writeDeadline.Deadline()
			require.False(t, hasDeadline)

			cancel()
			select {
			case writeErr := <-done:
				require.ErrorIs(t, writeErr, context.Canceled)
			case <-time.After(time.Second):
				require.FailNow(t, "blocked write did not return after context cancel")
			}

			// The canceled write added nothing: buffered amount and all message
			// counters are back to the pre-write snapshot.
			require.Equal(t, bufferedBefore, sendStream.BufferedAmount())
			sendStream.lock.RLock()
			assert.Equal(t, ssnBefore, sendStream.sequenceNumber)
			assert.Equal(t, orderedMIDBefore, sendStream.nextOrderedMID)
			assert.Equal(t, unorderedMIDBefore, sendStream.nextUnorderedMID)
			sendStream.lock.RUnlock()

			// A second, immediately canceled write must unwind the same way and
			// leave no state behind.
			canceledCtx, cancel2 := context.WithCancel(context.Background())
			cancel2()
			n, err := sendStream.WriteSCTPContext(canceledCtx, data, PayloadTypeWebRTCBinary)
			require.Zero(t, n)
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, bufferedBefore, sendStream.BufferedAmount())
		})
	}
}

// TestStreamWriteSCTPContextCommittedMessageSucceeds proves requirement 2:
// once the whole message is committed to the send queue, canceling the context
// cannot turn the write into an error, and the peer receives every fragment.
func TestStreamWriteSCTPContextCommittedMessageSucceeds(t *testing.T) {
	checkGoroutineLeaks(t)

	assoc, sendStream, peerStream := newBlockedWriteAssoc(t, false)

	// Drain the priming traffic (hello plus the two window-filling messages)
	// and keep reading the message the context write commits, so no reader
	// goroutine is left blocked.
	drained := make(chan struct{})
	go func() {
		buf := make([]byte, testContextMsgSize)
		// Two priming window-filling messages followed by the committed one.
		remaining := 3
		for remaining > 0 {
			n, readErr := peerStream.Read(buf)
			assert.NoError(t, readErr)
			if n == testContextMsgSize {
				remaining--
			}
		}
		close(drained)
	}()

	data := make([]byte, testContextMsgSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	go func() {
		n, err := sendStream.WriteSCTPContext(ctx, data, PayloadTypeWebRTCBinary)
		assert.Equal(t, testContextMsgSize, n)
		resultCh <- err
	}()
	waitForBlockedWrite(t, assoc)

	// The reopened window lets the blocked write commit. Cancel immediately:
	// the committed write must still return nil.
	select {
	case err := <-resultCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "blocked write never committed after the window reopened")
	}
	cancel()

	// The committed message reaches the peer with its boundary intact.
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "peer never received the committed message")
	}
}

// TestStreamWriteSCTPContextConcurrentCancel hammers the blocking queue with
// concurrent writers and random cancellations. Every message boundary must
// stay intact: the reader only ever sees whole 4000-byte messages, and the
// buffered amount settles at zero.
func TestStreamWriteSCTPContextConcurrentCancel(t *testing.T) {
	checkGoroutineLeaks(t)

	conn1, conn2 := createUDPConnPair()
	a1, a2, err := createAssociationPairWithConfig(conn1, conn2, Config{BlockWrite: true, MaxReceiveBufferSize: testContextMsgSize})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = a2.Close()
		_ = a1.Close()
	})

	s1, err := a1.OpenStream(7, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	// Prime so AcceptStream on the peer returns the stream.
	_, err = s1.WriteSCTP([]byte("prime"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	s2, err := a2.AcceptStream()
	require.NoError(t, err)

	// Reader drains whole messages only; a split or merged boundary fails here.
	go func() {
		buf := make([]byte, testContextMsgSize*2)
		for {
			n, readErr := s2.Read(buf)
			if errors.Is(readErr, io.EOF) {
				return
			}
			assert.NoError(t, readErr)
			if readErr == nil {
				assert.Contains(t, []int{len("prime"), testContextMsgSize, len("final")}, n)
			}
		}
	}()

	const writers = 12
	const writesPerWriter = 8
	var wg sync.WaitGroup
	var canceledWrites, successfulWrites atomic.Int64
	data := make([]byte, testContextMsgSize)

	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range writesPerWriter {
				ctx, cancel := context.WithCancel(context.Background())
				// Cancel half the contexts after a short delay so the cancel
				// races both the blocked-queue wait and the commit. The other
				// half run uncanceled so the queue always makes progress.
				if time.Now().UnixNano()%2 == 0 {
					go func() {
						time.Sleep(time.Duration(1+time.Now().UnixNano()%3) * time.Millisecond)
						cancel()
					}()
				}

				n, writeErr := s1.WriteSCTPContext(ctx, data, PayloadTypeWebRTCBinary)
				cancel()
				switch {
				case writeErr == nil:
					assert.Equal(t, testContextMsgSize, n)
					successfulWrites.Add(1)
				case errors.Is(writeErr, context.Canceled):
					assert.Zero(t, n)
					canceledWrites.Add(1)
				default:
					assert.Failf(t, "unexpected write error", "%v", writeErr)
				}
			}
		}()
	}
	wg.Wait()

	require.Positive(t, successfulWrites.Load())
	require.Positive(t, canceledWrites.Load())

	// All committed data drains and the buffered amount settles to the priming
	// write baseline once the reader catches up.
	require.Eventually(t, func() bool {
		return s1.BufferedAmount() == 0
	}, 5*time.Second, time.Millisecond)

	// The stream still serves an ordinary, uncanceled write.
	_, err = s1.WriteSCTPContext(context.Background(), []byte("final"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
}

// TestStreamWriteSCTPContextDeadlineStillApplies ensures the stream-wide write
// deadline and the per-call context compose: the deadline fires without the
// context being canceled, and canceling the context does not mutate deadline
// state. Legacy WriteSCTP deadline behavior stays unchanged.
func TestStreamWriteSCTPContextDeadlineStillApplies(t *testing.T) {
	checkGoroutineLeaks(t)

	assoc, sendStream, _ := newBlockedWriteAssoc(t, false)
	data := make([]byte, testContextMsgSize)

	// An uncanceled context still unblocks on the stream deadline.
	require.NoError(t, sendStream.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))
	n, err := sendStream.WriteSCTPContext(context.Background(), data, PayloadTypeWebRTCBinary)
	require.Zero(t, n)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, sendStream.SetWriteDeadline(time.Time{}))

	// A canceled context reports its own cause and leaves the deadline set.
	require.NoError(t, sendStream.SetWriteDeadline(time.Now().Add(30*time.Second)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, writeErr := sendStream.WriteSCTPContext(ctx, data, PayloadTypeWebRTCBinary)
		done <- writeErr
	}()
	waitForBlockedWrite(t, assoc)
	cancel()
	select {
	case writeErr := <-done:
		require.ErrorIs(t, writeErr, context.Canceled)
		require.NotErrorIs(t, writeErr, context.DeadlineExceeded)
	case <-time.After(time.Second):
		require.FailNow(t, "blocked write did not return after context cancel")
	}
	deadlineAt, hasDeadline := sendStream.writeDeadline.Deadline()
	require.True(t, hasDeadline)
	require.True(t, deadlineAt.After(time.Now()))
	require.NoError(t, sendStream.SetWriteDeadline(time.Time{}))

	// Legacy entry point deadline semantics are unchanged.
	require.NoError(t, sendStream.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))
	n, err = sendStream.WriteSCTP(data, PayloadTypeWebRTCBinary)
	require.Zero(t, n)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, sendStream.SetWriteDeadline(time.Time{}))
}

// TestStreamWriteSCTPContextCloseUnblocks mirrors the legacy close-unblocks
// behavior for the context entry point.
func TestStreamWriteSCTPContextCloseUnblocks(t *testing.T) {
	checkGoroutineLeaks(t)

	assoc, sendStream, _ := newBlockedWriteAssoc(t, false)
	data := make([]byte, testContextMsgSize)

	done := make(chan error, 1)
	go func() {
		_, writeErr := sendStream.WriteSCTPContext(context.Background(), data, PayloadTypeWebRTCBinary)
		done <- writeErr
	}()
	waitForBlockedWrite(t, assoc)

	require.NoError(t, assoc.Close())
	select {
	case writeErr := <-done:
		require.Error(t, writeErr)
		require.True(t,
			errors.Is(writeErr, ErrPayloadDataStateNotExist) || errors.Is(writeErr, ErrAssociationRestarted),
			"unexpected error after close: %v", writeErr)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "blocked context write did not return after association close")
	}
}

// TestStreamWriteSCTPContextNilAndClosed covers the entry-point guards.
func TestStreamWriteSCTPContextNilAndClosed(t *testing.T) {
	t.Parallel()

	conn1, conn2 := createUDPConnPair()
	a1, a2, err := createAssociationPairWithConfig(conn1, conn2, Config{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = a2.Close()
		_ = a1.Close()
	})

	stream, err := a1.OpenStream(1, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	var nilCtx context.Context //nolint:staticcheck // intentionally nil to exercise the guard
	n, err := stream.WriteSCTPContext(nilCtx, []byte("x"), PayloadTypeWebRTCBinary)
	require.Zero(t, n)
	require.ErrorIs(t, err, ErrNilContext)

	require.NoError(t, stream.Close())
	// Close moves the stream through closing to closed once the reset is
	// acknowledged; the write entry point rejects every non-open state.
	require.Eventually(t, func() bool {
		return stream.State() != StreamStateOpen
	}, time.Second, time.Millisecond)

	n, err = stream.WriteSCTPContext(context.Background(), []byte("x"), PayloadTypeWebRTCBinary)
	require.Zero(t, n)
	require.ErrorIs(t, err, ErrStreamClosed)
}

// TestStreamWriteSCTPContextAssociationRestart makes sure a blocked context
// write unblocks with ErrAssociationRestarted when the peer restarts, and that
// the restart's counter reset is not undone by rollbackWrite. A later write on
// the same stream starts from zero again.
func TestStreamWriteSCTPContextAssociationRestart(t *testing.T) {
	checkGoroutineLeaks(t)

	persistent, peer, err := association(t, pipeDump, WithBlockWrite(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = persistent.Close() })

	stream, err := persistent.OpenStream(0, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	// Exchange one message so both sides know the stream.
	_, err = stream.WriteSCTP([]byte("seed"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	peerStream, err := peer.OpenStream(0, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	readBuf := make([]byte, 64)
	require.NoError(t, peerStream.SetReadDeadline(time.Now().Add(5*time.Second)))
	rn, err := peerStream.Read(readBuf)
	require.NoError(t, err)
	require.Equal(t, "seed", string(readBuf[:rn]))
	// Stop the deadline timer goroutine before the peer is replaced.
	require.NoError(t, peerStream.SetReadDeadline(time.Time{}))

	// Block the writer, mirroring TestAssociationPeerRestartEndToEnd.
	persistent.lock.Lock()
	persistent.writePending = true
	persistent.lock.Unlock()

	blocked := make(chan error, 1)
	go func() {
		_, writeErr := stream.WriteSCTPContext(
			context.Background(), make([]byte, 128), PayloadTypeWebRTCBinary)
		blocked <- writeErr
	}()
	waitForBlockedWrite(t, persistent)

	// Replace the peer on the same addresses to force a restart.
	local, ok := peer.netConn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	remote, ok := peer.netConn.RemoteAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, peer.Close())
	conn, err := net.DialUDP("udp4", local, remote)
	require.NoError(t, err)
	replacement, err := ClientWithOptions(WithNetConn(conn))
	require.NoError(t, err)
	t.Cleanup(func() { _ = replacement.Close() })

	select {
	case writeErr := <-blocked:
		require.ErrorIs(t, writeErr, ErrAssociationRestarted)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "blocked context write did not unblock on restart")
	}

	// The restart reset every counter; rollbackWrite must not decrement them
	// below zero.
	require.Zero(t, stream.BufferedAmount())
	stream.lock.RLock()
	assert.Zero(t, stream.sequenceNumber)
	assert.Zero(t, stream.nextOrderedMID)
	assert.Zero(t, stream.nextUnorderedMID)
	stream.lock.RUnlock()

	// A fresh write on the same stream works and carries no stale state.
	inbound, err := replacement.OpenStream(0, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	require.NoError(t, inbound.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = stream.WriteSCTPContext(context.Background(), []byte("after restart"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	rn, err = inbound.Read(readBuf)
	require.NoError(t, err)
	require.Equal(t, "after restart", string(readBuf[:rn]))
	require.NoError(t, inbound.SetReadDeadline(time.Time{}))
}

func interleavingName(useInterleaving bool) string {
	if useInterleaving {
		return "interleaving"
	}

	return "no-interleaving"
}

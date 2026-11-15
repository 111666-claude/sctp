package sctp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/test"
	"github.com/stretchr/testify/require"
)

// testGracefulShutdownDraining verifies that data written immediately before
// Shutdown is fully delivered, in order, to the peer and that the shutdown
// handshake still completes when shutdown control chunks are lost.
//
// Scenarios:
//   - normal: no chunks are dropped.
//   - lostShutdown: the first shutdown control chunk (SHUTDOWN or
//     SHUTDOWN-ACK) is dropped and has to be retransmitted.
//   - lostDataAndShutdown: one DATA chunk and the first shutdown control
//     chunk are both dropped, exercising DATA retransmission and shutdown
//     retransmission together.
func testGracefulShutdownDraining(t *testing.T, dropShutdown, dropData bool) {
	const (
		numMessages = 10
		msgSize     = 1024
		streamID    = 777
	)

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(&vNetEnvConfig{
		minDelay:      10 * time.Millisecond,
		loggerFactory: loggerFactory,
		log:           log,
	})
	require.NoError(t, err)
	require.NotNil(t, venv)
	defer func() { _ = venv.wan.Stop() }()

	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)

	// Server: reads all messages back to back, then waits for association
	// shutdown.
	go func() {
		conn, dialErr := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
		)
		if dialErr != nil {
			serverDone <- dialErr
			return
		}
		defer func() { _ = conn.Close() }()

		assoc, assocErr := Server(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if assocErr != nil {
			serverDone <- assocErr
			return
		}
		defer func() { _ = assoc.Close() }()

		stream, acceptErr := assoc.AcceptStream()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}

		close(serverReady)

		// Drain the stream-opener message.
		opener := make([]byte, 4096)
		if _, _, readErr := stream.ReadSCTP(opener); readErr != nil {
			serverDone <- fmt.Errorf("server opener read: %w", readErr)
			return
		}

		received := make([][]byte, 0, numMessages)
		buf := make([]byte, 4096)
		for len(received) < numMessages {
			n, _, readErr := stream.ReadSCTP(buf)
			if readErr != nil {
				serverDone <- fmt.Errorf("server read after %d messages: %w", len(received), readErr)
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			received = append(received, msg)
		}

		for i, msg := range received {
			want := make([]byte, msgSize)
			want[0] = byte(i)
			want[msgSize-1] = byte(0xff - i)
			if !bytes.Equal(msg, want) {
				serverDone <- fmt.Errorf("server message %d mismatch (got len=%d)", i, len(msg))
				return
			}
		}

		// Wait until the association is fully torn down.
		select {
		case <-assoc.readLoopCloseCh:
		case <-time.After(15 * time.Second):
			serverDone <- fmt.Errorf("server association did not close")
			return
		}

		serverDone <- nil
	}()

	// Client: opens a stream, writes numMessages messages and immediately
	// initiates the graceful shutdown.
	go func() {
		conn, dialErr := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
		)
		if dialErr != nil {
			clientDone <- dialErr
			return
		}
		defer func() { _ = conn.Close() }()

		assoc, assocErr := Client(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if assocErr != nil {
			clientDone <- assocErr
			return
		}
		defer func() { _ = assoc.Close() }()

		stream, openErr := assoc.OpenStream(streamID, PayloadTypeWebRTCBinary)
		if openErr != nil {
			clientDone <- openErr
			return
		}

		// The peer-side stream is only created when the first DATA chunk
		// arrives; send an opener so AcceptStream() on the server returns.
		if _, writeErr := stream.Write([]byte("HELLO")); writeErr != nil {
			clientDone <- fmt.Errorf("client opener write: %w", writeErr)
			return
		}

		// Keep the retransmission timers short so dropped chunks (DATA or
		// shutdown control) are recovered quickly.
		assoc.lock.Lock()
		assoc.rtoMgr.setRTO(100, true)
		assoc.lock.Unlock()

		// Wait for the server to accept the stream before starting the
		// write-then-shutdown race.
		select {
		case <-serverReady:
		case <-time.After(10 * time.Second):
			clientDone <- fmt.Errorf("server did not become ready")
			return
		}

		for i := 0; i < numMessages; i++ {
			msg := make([]byte, msgSize)
			msg[0] = byte(i)
			msg[msgSize-1] = byte(0xff - i)
			if _, writeErr := stream.Write(msg); writeErr != nil {
				clientDone <- fmt.Errorf("client write %d: %w", i, writeErr)
				return
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if shutdownErr := assoc.Shutdown(ctx); shutdownErr != nil {
			clientDone <- fmt.Errorf("client shutdown: %w", shutdownErr)
			return
		}

		// After shutdown, new writes must be rejected.
		if _, writeErr := stream.Write([]byte{1}); writeErr == nil {
			clientDone <- fmt.Errorf("write after shutdown should fail")
			return
		}

		clientDone <- nil
	}()

	select {
	case <-serverReady:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not become ready")
	}

	if dropData {
		// Drop the first DATA chunk of the burst so it must be retransmitted
		// (the filter locks onto the first TSN and drops every copy until
		// the counter reaches zero).
		venv.dropNextDataChunk(2)
	}

	if dropShutdown {
		// Drop the first shutdown control chunk so the T2-shutdown timer
		// has to retransmit it.
		venv.dropNextShutdownChunks(1)
	}

	select {
	case err := <-clientDone:
		require.NoError(t, err, "client side failed")
	case <-time.After(20 * time.Second):
		t.Fatal("client did not finish shutdown in time (hung)")
	}

	select {
	case err := <-serverDone:
		require.NoError(t, err, "server side failed")
	case <-time.After(20 * time.Second):
		t.Fatal("server did not finish in time (hung)")
	}

	if dropShutdown {
		// The scheduled shutdown control chunk must actually have been
		// dropped (and recovered via retransmission).
		require.Equal(t, 0, venv.pendingShutdownDrops(), "scheduled shutdown chunk drop did not happen")
	}
}

func TestAssociation_GracefulShutdownDraining(t *testing.T) {
	lim := test.TimeOut(10 * time.Minute)
	defer lim.Stop()

	for round := 0; round < 10; round++ {
		t.Run(fmt.Sprintf("normal/round%d", round), func(t *testing.T) {
			testGracefulShutdownDraining(t, false, false)
		})
		t.Run(fmt.Sprintf("lostShutdownChunk/round%d", round), func(t *testing.T) {
			testGracefulShutdownDraining(t, true, false)
		})
		t.Run(fmt.Sprintf("lostDataAndShutdown/round%d", round), func(t *testing.T) {
			testGracefulShutdownDraining(t, true, true)
		})
	}
}

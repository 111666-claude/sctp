// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// truncatedCauseSamples are the six malformed error-cause samples with
// declared lengths that do not match the bytes actually present (0..5 bytes).
// None of them carries a complete 4-byte error-cause header.
func truncatedCauseSamples() [][]byte {
	return [][]byte{
		{},
		{0x00},
		{0x00, 0x0D},
		{0x00, 0x0D, 0x00},
		{0x00, 0x0D, 0x00, 0x08},       // header present, claims 8 bytes but has no value
		{0x00, 0x0D, 0x00, 0x08, 0x01}, // header present, claims 8 bytes but only 1 value byte
	}
}

func TestBuildErrorCauseRejectsTruncatedSamples(t *testing.T) {
	for i, sample := range truncatedCauseSamples() {
		t.Run("truncated sample", func(t *testing.T) {
			cause, err := buildErrorCause(sample)
			assert.Errorf(t, err, "sample %d (%d bytes) must be rejected, got cause %v",
				i, len(sample), cause)
			assert.Nil(t, cause)
		})
	}
}

// wrapCauseInChunk embeds a malformed cause fragment into a chunk body whose
// chunk-header length matches the actual number of bytes.
func wrapCauseInChunk(typ chunkType, fragment []byte) []byte {
	raw := make([]byte, chunkHeaderSize+len(fragment))
	raw[0] = byte(typ)
	raw[1] = 0x00
	raw[2] = byte(len(raw) >> 8)
	raw[3] = byte(len(raw))
	copy(raw[chunkHeaderSize:], fragment)

	return raw
}

func TestChunksRejectTruncatedCauses(t *testing.T) {
	// At the chunk level a 1..3 byte all-zero tail is RFC 9260 §3.2 chunk
	// padding and must be accepted, so only fragments long enough to look
	// like a cause header are exercised here. The shorter samples (including
	// the all-zero 1-byte one) are all rejected directly by buildErrorCause
	// in TestBuildErrorCauseRejectsTruncatedSamples.
	samples := truncatedCauseSamples()[4:]
	for i, sample := range samples {
		t.Run("ERROR truncated sample", func(t *testing.T) {
			c := &chunkError{}
			assert.Errorf(t, c.unmarshal(wrapCauseInChunk(ctError, sample)),
				"ERROR sample %d (%d bytes) must be rejected", i+4, len(sample))
		})

		t.Run("ABORT truncated sample", func(t *testing.T) {
			c := &chunkAbort{}
			assert.Errorf(t, c.unmarshal(wrapCauseInChunk(ctAbort, sample)),
				"ABORT sample %d (%d bytes) must be rejected", i+4, len(sample))
		})
	}
}

func TestChunkCausePadding(t *testing.T) {
	// A complete cause followed by 1..3 zero padding bytes is valid; the
	// same number of non-zero bytes is not.
	cause := []byte{0x00, 0x0D, 0x00, 0x04} // Protocol Violation, header only

	for pad := 1; pad <= 3; pad++ {
		body := append(append([]byte{}, cause...), make([]byte, pad)...)

		assert.NoError(t, (&chunkError{}).unmarshal(wrapCauseInChunk(ctError, body)),
			"ERROR with %d zero padding bytes should parse", pad)
		assert.NoError(t, (&chunkAbort{}).unmarshal(wrapCauseInChunk(ctAbort, body)),
			"ABORT with %d zero padding bytes should parse", pad)

		nonZero := append(append([]byte{}, cause...), make([]byte, pad)...)
		nonZero[len(nonZero)-1] = 0x01
		assert.Errorf(t, (&chunkError{}).unmarshal(wrapCauseInChunk(ctError, nonZero)),
			"ERROR with %d non-zero padding bytes must be rejected", pad)
		assert.Errorf(t, (&chunkAbort{}).unmarshal(wrapCauseInChunk(ctAbort, nonZero)),
			"ABORT with %d non-zero padding bytes must be rejected", pad)
	}
}

func TestChunksAcceptEmptyCauseList(t *testing.T) {
	// A zero-length cause area is valid: an ABORT/ERROR may carry no causes.
	assert.NoError(t, (&chunkError{}).unmarshal(wrapCauseInChunk(ctError, nil)))
	assert.NoError(t, (&chunkAbort{}).unmarshal(wrapCauseInChunk(ctAbort, nil)))
}

func TestErrorCauseMarshalRejectsOversizedValue(t *testing.T) {
	// RFC 9260 Cause Length is uint16: a 65536-byte value needs 65540 bytes,
	// which cannot be represented and must not silently truncate.
	const oversized = 65536
	value := make([]byte, oversized)

	t.Run("plain header", func(t *testing.T) {
		hdr := &errorCauseHeader{code: protocolViolation, raw: value}
		raw, err := hdr.marshal()
		assert.ErrorIs(t, err, ErrErrorCauseTooLong)
		assert.Nil(t, raw)
	})

	t.Run("protocol violation cause", func(t *testing.T) {
		cause := &errorCauseProtocolViolation{additionalInformation: value}
		raw, err := cause.marshal()
		assert.ErrorIs(t, err, ErrErrorCauseTooLong)
		assert.Nil(t, raw)
	})

	t.Run("user initiated abort cause", func(t *testing.T) {
		cause := &errorCauseUserInitiatedAbort{upperLayerAbortReason: value}
		raw, err := cause.marshal()
		assert.ErrorIs(t, err, ErrErrorCauseTooLong)
		assert.Nil(t, raw)
	})

	t.Run("inside an ERROR chunk", func(t *testing.T) {
		c := &chunkError{errorCauses: []errorCause{
			&errorCauseProtocolViolation{additionalInformation: value},
		}}
		raw, err := c.marshal()
		assert.ErrorIs(t, err, ErrErrorCauseTooLong)
		assert.Nil(t, raw)
	})
}

func TestErrorCauseMaxValueLengthRoundTrip(t *testing.T) {
	// The largest representable value (65535 - 4 = 65531 bytes) must still
	// marshal with an honest length and round-trip byte-for-byte.
	value := make([]byte, maxErrorCauseValueLength)
	for i := range value {
		value[i] = byte(i % 251)
	}

	hdr := &errorCauseHeader{code: protocolViolation, raw: value}
	raw, err := hdr.marshal()
	assert.NoError(t, err)
	assert.Len(t, raw, 1<<16-1, "full 65535-byte TLV must be written, not truncated")

	parsed, err := buildErrorCause(raw)
	assert.NoError(t, err)
	assert.Equal(t, protocolViolation, parsed.errorCauseCode())
	assert.Equal(t, uint16(1<<16-1), parsed.length())
	parsedHeader, ok := parsed.(*errorCauseProtocolViolation)
	assert.True(t, ok)
	assert.True(t, reflect.DeepEqual(value, parsedHeader.additionalInformation))
}

func TestErrorAndAbortCausesRoundTrip(t *testing.T) {
	unknownChunk := []byte{0xc0, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03}
	abortReason := []byte("upper-layer abort reason")
	const unknownCode errorCauseCode = 0x00FF

	buildCauses := func() []errorCause {
		return []errorCause{
			&errorCauseInvalidMandatoryParameter{},
			&errorCauseUnrecognizedChunkType{unrecognizedChunk: unknownChunk},
			&errorCauseProtocolViolation{additionalInformation: []byte("violation details")},
			&errorCauseUserInitiatedAbort{upperLayerAbortReason: abortReason},
			&errorCauseHeader{code: unknownCode, raw: []byte{0xAA, 0xBB, 0xCC}},
		}
	}

	// Repeatedly unmarshal and re-marshal the same inputs: results must stay
	// byte-for-byte identical across all 100 rounds for both chunk kinds.
	const rounds = 100

	t.Run("ERROR chunk", func(t *testing.T) {
		original, err := (&chunkError{errorCauses: buildCauses()}).marshal()
		assert.NoError(t, err)

		var wire []byte
		for round := 0; round < rounds; round++ {
			c := &chunkError{}
			assert.NoError(t, c.unmarshal(original))
			assert.Len(t, c.errorCauses, 5)
			wire, err = c.marshal()
			assert.NoError(t, err)
			assert.True(t, reflect.DeepEqual(original, wire),
				"ERROR round %d changed the wire bytes", round)
		}
	})

	t.Run("ABORT chunk", func(t *testing.T) {
		original, err := (&chunkAbort{errorCauses: buildCauses()}).marshal()
		assert.NoError(t, err)

		var wire []byte
		for round := 0; round < rounds; round++ {
			c := &chunkAbort{}
			assert.NoError(t, c.unmarshal(original))
			assert.Len(t, c.errorCauses, 5)

			// Known and unknown cause codes both survive the round trip.
			assert.Equal(t, invalidMandatoryParameter, c.errorCauses[0].errorCauseCode())
			assert.Equal(t, unrecognizedChunkType, c.errorCauses[1].errorCauseCode())
			assert.Equal(t, protocolViolation, c.errorCauses[2].errorCauseCode())
			assert.Equal(t, userInitiatedAbort, c.errorCauses[3].errorCauseCode())
			assert.Equal(t, unknownCode, c.errorCauses[4].errorCauseCode())

			wire, err = c.marshal()
			assert.NoError(t, err)
			assert.True(t, reflect.DeepEqual(original, wire),
				"ABORT round %d changed the wire bytes", round)
		}
	})
}

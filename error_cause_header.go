// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// errorCauseHeader represents the shared header that is shared by all error causes.
type errorCauseHeader struct {
	code errorCauseCode
	len  uint16
	raw  []byte
}

const (
	errorCauseHeaderLength = 4
	// maxErrorCauseValueLength is the largest cause value that fits with the
	// 4-byte header inside a uint16 Cause Length field (RFC 9260 §3.3.10).
	maxErrorCauseValueLength = 1<<16 - 1 - errorCauseHeaderLength
)

// Error cause errors.
var (
	ErrInvalidSCTPChunk   = errors.New("invalid SCTP chunk")
	ErrErrorCauseTooShort = errors.New("raw is too small for a SCTP error cause")
	ErrErrorCauseTooLong  = errors.New("error cause value is too long for the uint16 Cause Length field")
)

func (e *errorCauseHeader) marshal() ([]byte, error) {
	if len(e.raw) > maxErrorCauseValueLength {
		return nil, fmt.Errorf("%w: value length %d exceeds maximum %d",
			ErrErrorCauseTooLong, len(e.raw), maxErrorCauseValueLength)
	}

	e.len = uint16(len(e.raw)) + uint16(errorCauseHeaderLength) //nolint:gosec // G115
	raw := make([]byte, e.len)
	binary.BigEndian.PutUint16(raw[0:], uint16(e.code))
	binary.BigEndian.PutUint16(raw[2:], e.len)
	copy(raw[errorCauseHeaderLength:], e.raw)

	return raw, nil
}

func (e *errorCauseHeader) unmarshal(raw []byte) error {
	if len(raw) < errorCauseHeaderLength {
		return fmt.Errorf("%w: raw only %d bytes, %d is the minimum length",
			ErrErrorCauseTooShort, len(raw), errorCauseHeaderLength)
	}

	e.code = errorCauseCode(binary.BigEndian.Uint16(raw[0:]))
	e.len = binary.BigEndian.Uint16(raw[2:])
	if e.len < errorCauseHeaderLength || int(e.len) > len(raw) {
		return ErrInvalidSCTPChunk
	}
	valueLength := e.len - errorCauseHeaderLength
	e.raw = raw[errorCauseHeaderLength : errorCauseHeaderLength+valueLength]

	return nil
}

func (e *errorCauseHeader) length() uint16 {
	return e.len
}

func (e *errorCauseHeader) errorCauseCode() errorCauseCode {
	return e.code
}

// String makes errorCauseHeader printable.
func (e errorCauseHeader) String() string {
	return e.code.String()
}

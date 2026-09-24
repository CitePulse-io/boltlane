package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// clientHelloName reads one bounded TLS record. Fragmented, encrypted or
// malformed metadata is unverifiable and is refused by a hostname policy.
func clientHelloName(r io.Reader) (string, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != 22 || n < 4 || n > 16384 {
		return "", nil, ErrForbidden
	}
	record := make([]byte, 5+n)
	copy(record, header[:])
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		return "", nil, err
	}
	b := record[5:]
	if b[0] != 1 || int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b)-4 {
		return "", nil, ErrForbidden
	}
	b = b[4:]
	if len(b) < 35 {
		return "", nil, ErrForbidden
	}
	b = b[34:]
	skip := func(n int) error {
		if n > len(b) {
			return ErrForbidden
		}
		b = b[n:]
		return nil
	}
	if err := skip(1 + int(b[0])); err != nil {
		return "", nil, err
	}
	if len(b) < 2 {
		return "", nil, ErrForbidden
	}
	if err := skip(2 + int(binary.BigEndian.Uint16(b))); err != nil {
		return "", nil, err
	}
	if len(b) < 1 {
		return "", nil, ErrForbidden
	}
	if err := skip(1 + int(b[0])); err != nil {
		return "", nil, err
	}
	if len(b) < 2 {
		return "", nil, ErrForbidden
	}
	extLen := int(binary.BigEndian.Uint16(b))
	if err := skip(2); err != nil {
		return "", nil, err
	}
	if extLen != len(b) {
		return "", nil, ErrForbidden
	}
	for len(b) >= 4 {
		typ, size := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if err := skip(4); err != nil {
			return "", nil, err
		}
		if size > len(b) {
			return "", nil, ErrForbidden
		}
		if typ == 0 {
			x := b[:size]
			if len(x) < 5 || int(binary.BigEndian.Uint16(x)) != len(x)-2 || x[2] != 0 {
				return "", nil, ErrForbidden
			}
			nameLen := int(binary.BigEndian.Uint16(x[3:]))
			if nameLen == 0 || nameLen != len(x)-5 {
				return "", nil, ErrForbidden
			}
			name := string(x[5:])
			if strings.ContainsAny(name, "\x00/ :") || name != strings.ToLower(name) {
				return "", nil, ErrForbidden
			}
			return name, record, nil
		}
		if err := skip(size); err != nil {
			return "", nil, err
		}
	}
	return "", nil, errors.New("missing TLS server name")
}

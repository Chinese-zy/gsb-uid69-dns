package dnsname

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors describing the malformed-packet classes that Decode rejects.
var (
	ErrTruncated      = errors.New("dnsname: message is truncated")
	ErrPointerOutside = errors.New("dnsname: compression pointer targets outside the message")
	ErrPointerLoop    = errors.New("dnsname: compression pointer chain forms a loop")
	ErrLabelTooLong   = errors.New("dnsname: label runs past the end of the message")
	ErrJunkAfterName  = errors.New("dnsname: data follows the root label")
)

const maxCompressionJumps = 127

func EncodePlain(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name == "" {
		return []byte{0}
	}
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func Decode(pkt []byte) (string, error) {
	name, end, err := decodeName(pkt, 0)
	if err != nil {
		return "", err
	}
	if end != len(pkt) {
		return "", fmt.Errorf("%w: %d byte(s) after the terminating root label at offset %d", ErrJunkAfterName, len(pkt)-end, end)
	}
	return name, nil
}

// decodeName walks a possibly compressed name starting at off. It returns the
// decoded name (original label casing preserved) and the offset immediately
// after the root label (the pointer is two bytes, in which case end sits just
// past it).
func decodeName(pkt []byte, start int) (string, int, error) {
	var b strings.Builder
	off := start
	end := -1
	jumps := 0
	jumpedTo := make(map[int]bool)
loop:
	for {
		if off < 0 || off >= len(pkt) {
			return "", 0, fmt.Errorf("%w: label length byte at offset %d", ErrTruncated, off)
		}

		n := int(pkt[off])
		if n == 0 {
			if end < 0 {
				end = off + 1
			}
			break loop
		}
		switch {
		case n&0xC0 == 0xC0: // compression pointer
			if off+1 >= len(pkt) {
				return "", 0, fmt.Errorf("%w: second pointer byte at offset %d", ErrTruncated, off+1)
			}
			ptr := int(n&0x3F)<<8 | int(pkt[off+1])
			if ptr >= len(pkt) {
				return "", 0, fmt.Errorf("%w: pointer at offset %d targets %d, message is %d bytes", ErrPointerOutside, off, ptr, len(pkt))
			}
			jumps++
			if jumps > maxCompressionJumps {
				return "", 0, fmt.Errorf("%w: more than %d compression jumps", ErrPointerLoop, maxCompressionJumps)
			}
			if jumpedTo[ptr] {
				return "", 0, fmt.Errorf("%w: pointer target %d revisited", ErrPointerLoop, ptr)
			}
			jumpedTo[ptr] = true
			if end < 0 {
				end = off + 2
			}
			off = ptr
		case n < 64: // ordinary label
			if off+1+n > len(pkt) {
				return "", 0, fmt.Errorf("%w: %d-byte label at offset %d needs %d bytes, message has %d", ErrLabelTooLong, n, off, off+1+n, len(pkt))
			}
			b.Write(pkt[off+1 : off+1+n])
			b.WriteByte('.')
			off += 1 + n
		default:
			return "", 0, fmt.Errorf("dnsname: reserved label type %#x at offset %d", n&0xC0, off)
		}
	}
	return strings.TrimSuffix(b.String(), "."), end, nil
}

// CompressAgainst emits a message containing earlier followed by a compressed
// encoding of name, reusing earlier when name equals it or ends in the same
// labels. Offsets are byte offsets into the emitted message, never character
// counts.
func CompressAgainst(name, earlier string) []byte {
	name = strings.TrimSuffix(name, ".")
	earlier = strings.TrimSuffix(earlier, ".")
	base := EncodePlain(earlier)
	if name == earlier {
		return append(base, 0xC0, 0x00)
	}

	nameLabels := strings.Split(name, ".")
	earlierLabels := strings.Split(earlier, ".")

	// Labels in DNS are effectively ASCII; compare case-insensitively so a
	// restored name such as WWW.EXAMPLE.COM still compresses against
	// www.example.com, while the emitted leading labels keep their own case.
	if len(nameLabels) < len(earlierLabels) {
		return append(base, EncodePlain(name)...)
	}
	headCount := len(nameLabels) - len(earlierLabels)
	for j, label := range earlierLabels {
		if !strings.EqualFold(nameLabels[headCount+j], label) {
			return append(base, EncodePlain(name)...)
		}
	}
	out := make([]byte, 0, len(base)+len(name)+2)
	out = append(out, base...)
	for i := 0; i < headCount; i++ {
		label := nameLabels[i]
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0xC0, 0x00)
	return out
}

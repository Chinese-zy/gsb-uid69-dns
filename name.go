package dnsname

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrTruncated     = errors.New("dnsname: packet truncated")
	ErrPointerLoop   = errors.New("dnsname: compression pointer loop")
	ErrPointerRange  = errors.New("dnsname: compression pointer out of range")
	ErrJunkAfterRoot = errors.New("dnsname: junk after root label")
	ErrBadLabel      = errors.New("dnsname: invalid label length")
)

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
	var b strings.Builder
	off := 0
	jumped := false
	seen := map[int]bool{}
	for {
		if off >= len(pkt) {
			return "", fmt.Errorf("%w: offset %d beyond %d bytes", ErrTruncated, off, len(pkt))
		}
		n := int(pkt[off])
		if n == 0 {
			if !jumped && off+1 < len(pkt) {
				return "", fmt.Errorf("%w: %d trailing bytes", ErrJunkAfterRoot, len(pkt)-off-1)
			}
			break
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return "", fmt.Errorf("%w: pointer at offset %d missing second byte", ErrTruncated, off)
			}
			ptr := int(n&0x3F)<<8 | int(pkt[off+1])
			if ptr >= len(pkt) {
				return "", fmt.Errorf("%w: pointer to offset %d in %d byte packet", ErrPointerRange, ptr, len(pkt))
			}
			if seen[ptr] {
				return "", fmt.Errorf("%w: pointer to offset %d already visited", ErrPointerLoop, ptr)
			}
			seen[ptr] = true
			off = ptr
			jumped = true
			continue
		}
		if n&0xC0 != 0 {
			return "", fmt.Errorf("%w: reserved label type 0x%02x at offset %d", ErrBadLabel, n, off)
		}
		off++
		if off+n > len(pkt) {
			return "", fmt.Errorf("%w: label of %d bytes at offset %d exceeds %d byte packet", ErrTruncated, n, off, len(pkt))
		}
		label := string(pkt[off : off+n])
		b.WriteString(label)
		b.WriteByte('.')
		off += n
	}
	return strings.TrimSuffix(b.String(), "."), nil
}

func CompressAgainst(name, earlier string) []byte {
	name = strings.TrimSuffix(name, ".")
	earlier = strings.TrimSuffix(earlier, ".")
	base := EncodePlain(earlier)
	if name == earlier {
		return append([]byte{0xC0, 0x02}, base...)
	}
	suffix := "." + earlier
	if !strings.HasSuffix(name, suffix) {
		return EncodePlain(name)
	}
	head := strings.TrimSuffix(name, suffix)
	var out []byte
	for _, label := range strings.Split(head, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	off := len(out) + 2
	out = append(out, 0xC0, byte(off))
	return append(out, base...)
}

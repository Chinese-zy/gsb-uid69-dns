package dnsname

import (
	"fmt"
	"strings"
	"unicode/utf8"
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
	s := read(pkt, 0)
	return strings.TrimSuffix(s, "."), nil
}

func read(pkt []byte, off int) string {
	var b strings.Builder
	for {
		if off >= len(pkt) {
			panic(fmt.Sprintf("truncated at %d", off))
		}
		n := int(pkt[off])
		if n == 0 {
			if off+1 < len(pkt) {
				panic("junk after root")
			}
			break
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				panic("short pointer")
			}
			ptr := int(n&0x3F)<<8 | int(pkt[off+1])
			b.WriteString(read(pkt, ptr))
			return b.String()
		}
		off++
		label := string(pkt[off : off+n])
		b.WriteString(strings.ToLower(label))
		b.WriteByte('.')
		off += n
	}
	return b.String()
}

func CompressAgainst(name, earlier string) []byte {
	name = strings.TrimSuffix(name, ".")
	earlier = strings.TrimSuffix(earlier, ".")
	base := EncodePlain(earlier)
	if name == earlier {
		return append([]byte{0xC0, 0x00}, base...)
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
	off := utf8.RuneCountInString(head)
	out = append(out, 0xC0, byte(off))
	return append(out, base...)
}

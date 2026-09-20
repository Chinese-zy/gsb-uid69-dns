package dnsname

import (
	"errors"
	"testing"
)

func TestPlainRoundTrip(t *testing.T) {
	for _, name := range []string{"www.example.com", "a.b", ""} {
		pkt := EncodePlain(name)
		got, err := Decode(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if got != name {
			t.Fatalf("got %q want %q", got, name)
		}
	}
}

// TestNormalCompression decodes a hand-built message of the form
//
//	\3www\7example\3com\0 \3www\xc0\x04
//
// i.e. a full earlier name followed by a second name compressed against it.
// These are the shapes that used to parse and must keep parsing.
func TestNormalCompression(t *testing.T) {
	pkt := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'w', 'w', 'w', 0xC0, 0x04,
	}

	first, end, err := decodeName(pkt, 0)
	if err != nil {
		t.Fatalf("first name: %v", err)
	}
	if first != "www.example.com" {
		t.Fatalf("first name = %q", first)
	}

	second, _, err := decodeName(pkt, end)
	if err != nil {
		t.Fatalf("second name: %v", err)
	}
	if second != "www.example.com" {
		t.Fatalf("second name = %q want www.example.com", second)
	}

	// A message laid out as full name first, then a second name compressed
	// with a pointer to offset 0. Pointer offsets are absolute within the
	// message, so the second name must be decoded against the whole packet.
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'w', 'w', 'w', 0xC0, 0x00,
	}
	if got, _, err := decodeName(msg, 13); err != nil || got != "www.example.com" {
		t.Fatalf("decode second compressed name = %q, %v", got, err)
	}
}

// TestLabelCasePreserved ensures decode no longer folds label case.
func TestLabelCasePreserved(t *testing.T) {
	pkt := []byte{3, 'W', 'W', 'W', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "WWW.Example" {
		t.Fatalf("got %q, case must be preserved", got)
	}
}

func TestMalformedPackets(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{
			name: "pointer points at itself",
			pkt:  []byte{0xC0, 0x00},
			want: ErrPointerLoop,
		},
		{
			name: "two-hop pointer loop",
			pkt:  []byte{0xC0, 0x02, 0xC0, 0x00},
			want: ErrPointerLoop,
		},
		{
			name: "truncated label body",
			pkt:  []byte{4, 'a', 'b'},
			want: ErrLabelTooLong,
		},
		{
			name: "truncated length byte",
			pkt:  []byte{1, 'a'},
			want: ErrTruncated,
		},
		{
			name: "short pointer",
			pkt:  []byte{1, 'a', 0xC0},
			want: ErrTruncated,
		},
		{
			name: "pointer beyond message",
			pkt:  []byte{1, 'a', 0xC0, 0x20},
			want: ErrPointerOutside,
		},
		{
			name: "junk after root label",
			pkt:  []byte{0, 0x42},
			want: ErrJunkAfterName,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.pkt)
			if err == nil {
				t.Fatalf("Decode(% x) succeeded, want error", tc.pkt)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decode(% x) error = %v, want class %v", tc.pkt, err, tc.want)
			}
		})
	}
}

func TestCompressAgainst(t *testing.T) {
	// earlier encoded first, pointer at the end must target byte offset 0.
	pkt := CompressAgainst("www.example.com", "example.com")
	baseLen := len(EncodePlain("example.com"))
	if got, _, err := decodeName(pkt, baseLen); err != nil || got != "www.example.com" {
		t.Fatalf("decode compressed second name = %q, %v", got, err)
	}
	// Layout: base "example.com" then "\3www\xc0\x00".
	if pkt[len(pkt)-2] != 0xC0 || pkt[len(pkt)-1] != 0x00 {
		t.Fatalf("pointer bytes = % x, want c000", pkt[len(pkt)-2:])
	}

	// Equal names collapse to a bare pointer at offset 0.
	eq := CompressAgainst("example.com", "example.com")
	if got, _, err := decodeName(eq, baseLen); err != nil || got != "example.com" {
		t.Fatalf("equal-name compress = %q, %v", got, err)
	}

	// No shared suffix: plain encoding appended after base, still decodable
	// when the emitted second name is parsed standalone.
	noMatch := CompressAgainst("other.net", "example.com")
	second := noMatch[len(EncodePlain("example.com")):]
	if got, err := Decode(second); err != nil || got != "other.net" {
		t.Fatalf("plain fallback = %q, %v", got, err)
	}
}

// TestCompressByteOffsetNotCharCount guards the original bug where the pointer
// offset was computed from rune counts of the head labels. Using multibyte
// labels keeps that distinction sharp: the target must be a real byte offset.
func TestCompressByteOffsetNotCharCount(t *testing.T) {
	pkt := CompressAgainst("éx.éxample.com", "éxample.com")
	baseLen := len(EncodePlain("éxample.com"))
	if got, _, err := decodeName(pkt, baseLen); err != nil || got != "éx.éxample.com" {
		t.Fatalf("multibyte compress round trip = %q, %v", got, err)
	}

	// Case-insensitive reuse must still produce a valid pointer message.
	mixed := CompressAgainst("WWW.Example.COM", "example.com")
	// The pointer-reused suffix is rendered from the earlier name's bytes, so
	// only the locally encoded head labels keep the new name's casing.
	if got, _, err := decodeName(mixed, len(EncodePlain("example.com"))); err != nil || got != "WWW.example.com" {
		t.Fatalf("case-insensitive compress = %q, %v", got, err)
	}
}

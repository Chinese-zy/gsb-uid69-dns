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

// 正常压缩包： "www" + 指针到偏移 7 的 "example.com"。
func TestDecodeCompressed(t *testing.T) {
	pkt := []byte{
		3, 'w', 'w', 'w', 0xC0, 0x07,
		0, // 填充，让 example 落在偏移 7
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	}
	_ = pkt
	// 布局重排：名字从 0 开始，指针目标必须指向报文内的后缀。
	pkt = []byte{
		3, 'w', 'w', 'w', 0xC0, 0x0C,
		0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	}
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "www.example.com" {
		t.Fatalf("got %q", got)
	}
}

// 标签大小写必须保留。
func TestDecodePreservesCase(t *testing.T) {
	pkt := []byte{3, 'W', 'w', 'W', 7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 0}
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "WwW.ExAmpLe" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeBadPackets(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"指针指回自己", []byte{0xC0, 0x00}, ErrPointerLoop},
		{"两跳绕圈", []byte{0xC0, 0x02, 0xC0, 0x00}, ErrPointerLoop},
		{"标签截断", []byte{5, 'a', 'b'}, ErrTruncated},
		{"指针第二字节缺失", []byte{0xC0}, ErrTruncated},
		{"空报文", nil, ErrTruncated},
		{"指针跳出报文", []byte{0xC0, 0x7F}, ErrPointerRange},
		{"根标签后有垃圾", []byte{0, 0, 0}, ErrJunkAfterRoot},
		{"保留标签类型", []byte{0x40, 'a', 0}, ErrBadLabel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.pkt)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v want %v", err, c.want)
			}
		})
	}
}

// 压缩结果必须能再解回原名字，且指针落在后缀的字节偏移上。
func TestCompressRoundTrip(t *testing.T) {
	pkt := CompressAgainst("www.example.com", "example.com")
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "www.example.com" {
		t.Fatalf("got %q", got)
	}
	// 头部 "www" 编码占 4 字节，指针占 2 字节，后缀在偏移 6。
	if pkt[4] != 0xC0 || pkt[5] != 0x06 {
		t.Fatalf("pointer bytes %x %x", pkt[4], pkt[5])
	}
}

// 多字节字符时指针偏移按字节算，不能按字符数。
func TestCompressMultibyteHead(t *testing.T) {
	pkt := CompressAgainst("中文.example.com", "example.com")
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "中文.example.com" {
		t.Fatalf("got %q", got)
	}
	// "中文" 是 6 字节，加长度字节和指针共 9 字节，后缀在偏移 9。
	if pkt[7] != 0xC0 || pkt[8] != 0x09 {
		t.Fatalf("pointer bytes at 7: %x %x", pkt[7], pkt[8])
	}
}

func TestCompressIdenticalName(t *testing.T) {
	pkt := CompressAgainst("example.com", "example.com")
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.com" {
		t.Fatalf("got %q", got)
	}
}

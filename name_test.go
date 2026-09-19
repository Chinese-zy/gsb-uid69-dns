package dnsname

import "testing"

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

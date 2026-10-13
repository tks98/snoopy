package output

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeSection(t *testing.T, d *qpackDecoder, hexBytes string) string {
	t.Helper()
	fields, err := d.fieldSection(unhex(t, hexBytes))
	if err != nil {
		t.Fatalf("field section %s: %v", hexBytes, err)
	}
	var out []string
	for _, f := range fields {
		out = append(out, f.Name+"="+f.Value)
	}
	return strings.Join(out, " ")
}

// The examples of RFC 9204, Appendix B, in order: each builds on the table
// the previous ones left.
func TestQPACKExamples(t *testing.T) {
	var d qpackDecoder

	// B.1: literal field line with a static name reference.
	if got := decodeSection(t, &d, "0000 510b 2f69 6e64 6578 2e68 746d 6c"); got != ":path=/index.html" {
		t.Errorf("B.1: %s", got)
	}

	// B.2: capacity, two inserts with static name references, and a
	// field section using post-base indexes; its encoder stream data arrives
	// in two pieces, the first cut inside an instruction.
	enc := unhex(t, "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
	if _, err := d.fieldSection(unhex(t, "0381 10 11")); !errors.Is(err, errBlocked) {
		t.Errorf("B.2 before the encoder stream: %v", err)
	}
	if err := d.encoderStream(enc[:10]); err != nil {
		t.Fatal(err)
	}
	if err := d.encoderStream(enc[10:]); err != nil {
		t.Fatal(err)
	}
	if d.inserted != 2 || d.size != 106 {
		t.Errorf("B.2: %d inserted, size %d", d.inserted, d.size)
	}
	if got := decodeSection(t, &d, "0381 10 11"); got != ":authority=www.example.com :path=/sample/path" {
		t.Errorf("B.2: %s", got)
	}

	// B.3: insert with a literal name.
	if err := d.encoderStream(unhex(t, "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565")); err != nil {
		t.Fatal(err)
	}
	if d.inserted != 3 || d.size != 160 {
		t.Errorf("B.3: %d inserted, size %d", d.inserted, d.size)
	}

	// B.4: duplicate, then relative dynamic and static references.
	if err := d.encoderStream(unhex(t, "02")); err != nil {
		t.Fatal(err)
	}
	if got := decodeSection(t, &d, "0500 80 c1 81"); got != ":authority=www.example.com :path=/ custom-key=custom-value" {
		t.Errorf("B.4: %s", got)
	}

	// B.5: insert with a dynamic name reference, which evicts the oldest
	// entry (:authority) to stay within 220 bytes.
	if err := d.encoderStream(unhex(t, "810d 6375 7374 6f6d 2d76 616c 7565 32")); err != nil {
		t.Fatal(err)
	}
	if d.inserted != 5 || d.size != 215 || len(d.entries) != 4 { // RFC 9204 says Size=215
		t.Errorf("B.5: %d inserted, size %d, %d entries", d.inserted, d.size, len(d.entries))
	}
	if _, err := d.entry(0); err == nil {
		t.Error("B.5: evicted entry still there")
	}
	if e, err := d.entry(4); err != nil || e != [2]string{"custom-key", "custom-value2"} {
		t.Errorf("B.5: entry 4 is %q, %v", e, err)
	}
}

func TestQPACKHuffman(t *testing.T) {
	var d qpackDecoder
	// A literal with a static name reference (:authority, 0x50) and a
	// Huffman-coded value: "www.example.com" as coded in RFC 7541, C.4.1.
	got := decodeSection(t, &d, "0000 50 8c f1e3 c2e5 f23a 6ba0 ab90 f4ff")
	if got != ":authority=www.example.com" {
		t.Errorf("got %s", got)
	}
}

// The Required Insert Count wraps at twice the table's maximum number of
// entries (RFC 9204, section 4.5.1.1).
func TestQPACKRequiredInsertCountWraps(t *testing.T) {
	d := qpackDecoder{maxEntries: 2} // a 64-byte table
	if err := d.encoderStream(unhex(t, "3f21")); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := d.encoderStream([]byte{0x41, 'a', 0x02, 'v', byte('0' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Required Insert Count 5, sent as 5 mod 4 + 1; base 5; entry 4.
	if got := decodeSection(t, &d, "02 00 80"); got != "a=v4" {
		t.Errorf("got %s", got)
	}
	for _, tc := range []struct {
		encoded uint64
		want    int
	}{{0, 0}, {1, 4}, {2, 5}, {3, 6}, {4, 7}} {
		if got, err := d.requiredInsertCount(tc.encoded); err != nil || got != tc.want {
			t.Errorf("encoded %d: %d %v, want %d", tc.encoded, got, err, tc.want)
		}
	}
	if _, err := d.requiredInsertCount(5); err == nil {
		t.Error("accepted an encoded count beyond the range")
	}
}

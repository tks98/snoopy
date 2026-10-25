package output

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

var (
	// errShort means the input ends in the middle of an instruction.
	errShort = errors.New("qpack: input cut off")
	// errBlocked means a field section refers to dynamic table entries
	// whose insertions haven't been seen yet.
	errBlocked = errors.New("qpack: waiting for encoder stream")
	// errFieldsCut comes with a field section's fields when some were left
	// out, to keep them under maxHeaderList.
	errFieldsCut = fmt.Errorf("decoded to more than %d KiB; the rest of its fields aren't shown", maxHeaderList>>10)
)

const (
	// The largest dynamic table followed. Chrome advertises 64 KiB
	// (SETTINGS_QPACK_MAX_TABLE_CAPACITY), others less; as with HPACK, a
	// larger table only makes room for a header to be repeated many times.
	maxQPACKCapacity = 64 << 10
	// The longest encoder instruction: one inserting an entry the table can
	// hold, with Huffman codes of up to 30 bits per byte.
	maxQPACKInstruction = 4*maxQPACKCapacity + 32
)

// qpackDecoder decodes the field sections (header blocks) sent in one
// direction of an HTTP/3 connection (RFC 9204). The sender's encoder stream
// goes the same way and builds the dynamic table that field sections may
// refer to.
type qpackDecoder struct {
	capacity int
	size     int
	entries  [][2]string // dynamic table, oldest first
	inserted int         // insertions so far; the absolute index of the next
	pending  []byte      // encoder stream bytes ending in a cut-off instruction
	// The most entries the table can hold, from the capacity the receiver
	// advertised; 0 if that isn't known.
	maxEntries int
	// The capacity the receiver advertised, if maxKnown.
	maxCapacity int64
	maxKnown    bool
}

// encoderStream processes the next bytes of the encoder stream.
func (d *qpackDecoder) encoderStream(b []byte) error {
	d.pending = append(d.pending, b...)
	for len(d.pending) > 0 {
		n, err := d.instruction(d.pending)
		if errors.Is(err, errShort) {
			if len(d.pending) > maxQPACKInstruction {
				return fmt.Errorf("qpack: encoder instruction longer than %d bytes", maxQPACKInstruction)
			}
			return nil
		}
		if err != nil {
			return err
		}
		d.pending = d.pending[n:]
	}
	d.pending = nil // let the array go
	return nil
}

// instruction applies one encoder instruction and returns its length.
func (d *qpackDecoder) instruction(b []byte) (int, error) {
	switch {
	case b[0]&0x80 != 0: // Insert with name reference: 1 T index(6), value
		static := b[0]&0x40 != 0
		index, n, err := qpackInt(b, 6)
		if err != nil {
			return 0, err
		}
		value, m, err := qpackString(b[n:], 7)
		if err != nil {
			return 0, err
		}
		var name string
		if static {
			if index >= uint64(len(qpackStatic)) {
				return 0, fmt.Errorf("qpack: static index %d", index)
			}
			name = qpackStatic[index][0]
		} else {
			e, err := d.entry(d.inserted - 1 - int(index))
			if err != nil {
				return 0, err
			}
			name = e[0]
		}
		return n + m, d.insert(name, value)
	case b[0]&0xc0 == 0x40: // Insert with literal name: 01 H len(5) name, value
		name, n, err := qpackString(b, 5)
		if err != nil {
			return 0, err
		}
		value, m, err := qpackString(b[n:], 7)
		if err != nil {
			return 0, err
		}
		return n + m, d.insert(name, value)
	case b[0]&0xe0 == 0x20: // Set dynamic table capacity: 001 capacity(5)
		capacity, n, err := qpackInt(b, 5)
		if err != nil {
			return 0, err
		}
		if d.maxKnown && capacity > uint64(d.maxCapacity) {
			return 0, fmt.Errorf("qpack: table capacity %d exceeds the advertised maximum %d", capacity, d.maxCapacity)
		}
		if capacity > maxQPACKCapacity {
			return 0, fmt.Errorf("qpack: table capacity of %d bytes is more than snoopy follows (%d)", capacity, maxQPACKCapacity)
		}
		d.capacity = int(capacity)
		d.evict(0)
		return n, nil
	default: // Duplicate: 000 index(5)
		index, n, err := qpackInt(b, 5)
		if err != nil {
			return 0, err
		}
		e, err := d.entry(d.inserted - 1 - int(index))
		if err != nil {
			return 0, err
		}
		return n, d.insert(e[0], e[1])
	}
}

func (d *qpackDecoder) insert(name, value string) error {
	size := len(name) + len(value) + 32
	if size > d.capacity {
		return fmt.Errorf("qpack: entry of %d bytes exceeds the table's capacity of %d", size, d.capacity)
	}
	d.evict(size)
	d.entries = append(d.entries, [2]string{name, value})
	d.size += size
	d.inserted++
	return nil
}

// evict drops the oldest entries until room more bytes fit.
func (d *qpackDecoder) evict(room int) {
	for len(d.entries) > 0 && d.size+room > d.capacity {
		e := d.entries[0]
		d.size -= len(e[0]) + len(e[1]) + 32
		d.entries = d.entries[1:]
	}
}

// entry returns the dynamic table entry with the given absolute index.
func (d *qpackDecoder) entry(abs int) ([2]string, error) {
	first := d.inserted - len(d.entries)
	if abs < first || abs >= d.inserted {
		return [2]string{}, fmt.Errorf("qpack: no dynamic table entry %d", abs)
	}
	return d.entries[abs-first], nil
}

// fieldSection decodes an encoded field section (a HEADERS frame's payload).
// If the fields come to more than maxHeaderList, it returns those that fit
// and errFieldsCut.
func (d *qpackDecoder) fieldSection(b []byte) ([]hpack.HeaderField, error) {
	encodedRIC, n, err := qpackInt(b, 8)
	if err != nil {
		return nil, err
	}
	b = b[n:]
	if len(b) == 0 {
		return nil, errShort
	}
	negative := b[0]&0x80 != 0
	delta, n, err := qpackInt(b, 7)
	if err != nil {
		return nil, err
	}
	b = b[n:]
	ric, err := d.requiredInsertCount(encodedRIC)
	if err != nil {
		return nil, err
	}
	if ric > d.inserted {
		return nil, errBlocked
	}
	base := ric + int(delta)
	if negative {
		base = ric - int(delta) - 1
	}

	var fields []hpack.HeaderField
	size := 0
	add := func(f hpack.HeaderField) bool { // false once over maxHeaderList
		size += int(f.Size())
		if size > maxHeaderList {
			return false
		}
		fields = append(fields, f)
		return true
	}
	dynamic := func(abs int) ([2]string, error) {
		if abs >= ric {
			return [2]string{}, fmt.Errorf("qpack: reference to entry %d beyond the required insert count %d", abs, ric)
		}
		return d.entry(abs)
	}
	static := func(index uint64) ([2]string, error) {
		if index >= uint64(len(qpackStatic)) {
			return [2]string{}, fmt.Errorf("qpack: static index %d", index)
		}
		return qpackStatic[index], nil
	}
	for len(b) > 0 {
		var e [2]string
		var value string
		var m int
		switch {
		case b[0]&0x80 != 0: // Indexed field line: 1 T index(6)
			index, n, err := qpackInt(b, 6)
			if err != nil {
				return nil, err
			}
			if b[0]&0x40 != 0 {
				e, err = static(index)
			} else {
				e, err = dynamic(base - 1 - int(index))
			}
			if err != nil {
				return nil, err
			}
			if !add(hpack.HeaderField{Name: e[0], Value: e[1]}) {
				return fields, errFieldsCut
			}
			b = b[n:]
			continue
		case b[0]&0xc0 == 0x40: // Literal with name reference: 01 N T index(4), value
			index, n, err := qpackInt(b, 4)
			if err != nil {
				return nil, err
			}
			if b[0]&0x10 != 0 {
				e, err = static(index)
			} else {
				e, err = dynamic(base - 1 - int(index))
			}
			if err != nil {
				return nil, err
			}
			value, m, err = qpackString(b[n:], 7)
			if err != nil {
				return nil, err
			}
			m += n
		case b[0]&0xe0 == 0x20: // Literal with literal name: 001 N H len(3) name, value
			name, n, err := qpackString(b, 3)
			if err != nil {
				return nil, err
			}
			value, m, err = qpackString(b[n:], 7)
			if err != nil {
				return nil, err
			}
			e[0] = name
			m += n
		case b[0]&0xf0 == 0x10: // Indexed field line with post-base index: 0001 index(4)
			index, n, err := qpackInt(b, 4)
			if err != nil {
				return nil, err
			}
			if e, err = dynamic(base + int(index)); err != nil {
				return nil, err
			}
			if !add(hpack.HeaderField{Name: e[0], Value: e[1]}) {
				return fields, errFieldsCut
			}
			b = b[n:]
			continue
		default: // Literal with post-base name reference: 0000 N index(3), value
			index, n, err := qpackInt(b, 3)
			if err != nil {
				return nil, err
			}
			if e, err = dynamic(base + int(index)); err != nil {
				return nil, err
			}
			value, m, err = qpackString(b[n:], 7)
			if err != nil {
				return nil, err
			}
			m += n
		}
		if !add(hpack.HeaderField{Name: e[0], Value: value}) {
			return fields, errFieldsCut
		}
		b = b[m:]
	}
	return fields, nil
}

// requiredInsertCount decodes a field section's Required Insert Count, which
// is sent modulo twice the table's maximum number of entries (RFC 9204,
// section 4.5.1.1). If that maximum isn't known, it assumes the count
// hasn't wrapped, which holds for a connection's first 2 * (maximum
// capacity / 32) insertions.
func (d *qpackDecoder) requiredInsertCount(encoded uint64) (int, error) {
	if encoded == 0 {
		return 0, nil
	}
	if d.maxEntries <= 0 { // the table's capacity is unknown: assume no wrapping
		return max(int(min(encoded, 1<<40))-1, 1), nil
	}
	fullRange := 2 * d.maxEntries
	if encoded > uint64(fullRange) {
		return 0, fmt.Errorf("qpack: encoded required insert count %d exceeds %d", encoded, fullRange)
	}
	maxValue := d.inserted + d.maxEntries
	ric := maxValue/fullRange*fullRange + int(encoded) - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, fmt.Errorf("qpack: invalid required insert count %d", encoded)
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, fmt.Errorf("qpack: invalid required insert count %d", encoded)
	}
	return ric, nil
}

// qpackInt decodes a prefixed integer (RFC 7541, section 5.1) whose prefix
// is the low bits of b[0], and returns it with the bytes it took.
func qpackInt(b []byte, bits uint) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errShort
	}
	max := uint64(1)<<bits - 1
	v := uint64(b[0]) & max
	if v < max {
		return v, 1, nil
	}
	for i, shift := 1, uint(0); i < len(b); i, shift = i+1, shift+7 {
		if shift > 56 {
			return 0, 0, errors.New("qpack: integer too large")
		}
		v += uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errShort
}

// qpackString decodes a string literal whose length has a prefix of the
// given bits, with the Huffman flag in the bit above it.
func qpackString(b []byte, bits uint) (string, int, error) {
	if len(b) == 0 {
		return "", 0, errShort
	}
	huffman := b[0]&(1<<bits) != 0
	length, n, err := qpackInt(b, bits)
	if err != nil {
		return "", 0, err
	}
	if uint64(len(b)-n) < length {
		return "", 0, errShort
	}
	raw := b[n : n+int(length)]
	if !huffman {
		return string(raw), n + int(length), nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", 0, fmt.Errorf("qpack: %w", err)
	}
	return s, n + int(length), nil
}

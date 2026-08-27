package canonical

import (
	"bytes"
	"fmt"
)

// CanonicalSetArray validates that elements form a canonical set-like array and
// returns the array's canonical bytes. Each element is canonicalized on its own,
// and the elements must then appear in strictly ascending order of their
// canonical bytes. Strict ascent fixes both halves of the rule at once: it is the
// ordering ("set-like arrays sorted by their canonical element bytes") and it
// rejects duplicates (two equal canonical elements are never strictly ascending).
//
// This is a schema-level rule, deliberately separate from Canonicalize: RFC 8785
// treats a JSON array as an ordered sequence and neither sorts nor de-duplicates
// it, because for most arrays order is meaningful. Only a schema knows that a
// particular array is a set, so only a schema-aware producer or verifier calls
// this. Arrays whose order carries meaning stay with Canonicalize/Marshal.
//
// Each element is the raw JSON bytes of one value; the elements slice is treated
// as read-only.
func CanonicalSetArray(elements [][]byte) ([]byte, error) {
	canonicalElements := make([][]byte, len(elements))
	for index, element := range elements {
		canonicalElement, err := Canonicalize(element)
		if err != nil {
			return nil, fmt.Errorf("canonical: set element %d: %w", index, err)
		}
		canonicalElements[index] = canonicalElement
	}

	for index := 1; index < len(canonicalElements); index++ {
		switch bytes.Compare(canonicalElements[index-1], canonicalElements[index]) {
		case 0:
			return nil, fmt.Errorf("canonical: duplicate set element at index %d", index)
		case 1:
			return nil, fmt.Errorf(
				"canonical: set element at index %d is out of canonical order", index,
			)
		}
	}

	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for index, canonicalElement := range canonicalElements {
		if index > 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(canonicalElement)
	}
	buffer.WriteByte(']')
	return buffer.Bytes(), nil
}

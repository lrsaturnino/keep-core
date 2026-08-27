package canonical

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"
	"unicode/utf8"
)

// MaxCBORDepth bounds adversarial nesting while decoding or encoding. The
// frozen ledger schemas are shallow; 64 leaves ample room for nested payloads
// without making stack or CPU exhaustion part of the accepted format.
const MaxCBORDepth = 64

// CBORNegative represents the CBOR major-type-1 argument N, whose mathematical
// value is -1-N. It preserves the complete CBOR negative-integer range down to
// -2^64, which cannot be represented by a Go int64.
type CBORNegative uint64

// CBORArray and CBORMap are the lossless generic model returned by DecodeCBOR.
// A map is an ordered entry list rather than a Go map so key type, canonical
// key ordering, and duplicate rejection survive a decode/re-encode cycle.
type CBORArray []any

type CBORMapEntry struct {
	Key   any
	Value any
}

type CBORMap []CBORMapEntry

// MarshalCBOR encodes the deliberately small RFC 8949 data model used by the
// ledger: integers, byte/text strings, arrays, maps, booleans, and null. It
// always emits core deterministic encoding: definite lengths, preferred
// (shortest) integer/length arguments, and map keys ordered lexicographically
// by their deterministic encoded bytes. Floats, tags, undefined/simple values,
// and indefinite-length items have no representation and are rejected.
func MarshalCBOR(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := encodeCBOR(
		&buffer,
		reflect.ValueOf(value),
		0,
		map[cborVisit]bool{},
	); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// DecodeCBOR accepts exactly one core-deterministic CBOR value. It is a strict
// verifier, not a normalizer: a semantically equivalent non-shortest integer,
// an unsorted map, an indefinite value, a tag, or a float is rejected.
func DecodeCBOR(input []byte) (any, error) {
	decoder := cborDecoder{input: input}
	value, err := decoder.decode(0)
	if err != nil {
		return nil, err
	}
	if decoder.offset != len(input) {
		return nil, fmt.Errorf(
			"canonical: trailing CBOR data at byte %d", decoder.offset,
		)
	}
	return value, nil
}

// CanonicalizeCBOR validates input and returns an independent copy. Unlike the
// JSON canonicalizer, this function never repairs a non-deterministic encoding:
// stored ledger bytes are themselves the identity and alternatives must fail.
func CanonicalizeCBOR(input []byte) ([]byte, error) {
	value, err := DecodeCBOR(input)
	if err != nil {
		return nil, err
	}
	reencoded, err := MarshalCBOR(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(input, reencoded) {
		return nil, fmt.Errorf("canonical: CBOR value does not re-encode identically")
	}
	return append([]byte(nil), input...), nil
}

type cborVisit struct {
	typeOf  reflect.Type
	pointer uintptr
}

func encodeCBOR(
	buffer *bytes.Buffer,
	value reflect.Value,
	depth int,
	seen map[cborVisit]bool,
) error {
	if depth > MaxCBORDepth {
		return fmt.Errorf("canonical: CBOR nesting exceeds %d", MaxCBORDepth)
	}
	if !value.IsValid() {
		buffer.WriteByte(0xf6) // null
		return nil
	}

	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			buffer.WriteByte(0xf6)
			return nil
		}
		return encodeCBOR(buffer, value.Elem(), depth, seen)
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			buffer.WriteByte(0xf6)
			return nil
		}
		key := cborVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if seen[key] {
			return fmt.Errorf("canonical: cyclic CBOR pointer value")
		}
		seen[key] = true
		defer delete(seen, key)
		return encodeCBOR(buffer, value.Elem(), depth+1, seen)
	}

	// Maps and non-byte slices can refer back to themselves through interface
	// values. Reject cycles explicitly instead of relying on the depth bound to
	// stop them after repeated work. Repeated non-cyclic aliases remain valid
	// because each visit is removed on return.
	if (value.Kind() == reflect.Map ||
		(value.Kind() == reflect.Slice && value.Type().Elem().Kind() != reflect.Uint8)) &&
		!value.IsNil() {
		key := cborVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if seen[key] {
			return fmt.Errorf("canonical: cyclic CBOR map or slice value")
		}
		seen[key] = true
		defer delete(seen, key)
	}

	// These named model types must be recognized before their underlying kinds.
	if value.Type() == reflect.TypeOf(CBORNegative(0)) {
		writeCBORHead(buffer, 1, uint64(value.Interface().(CBORNegative)))
		return nil
	}
	if value.Type() == reflect.TypeOf(CBORMap{}) {
		return encodeCBORMap(buffer, value.Interface().(CBORMap), depth, seen)
	}
	if value.Type() == reflect.TypeOf(CBORArray{}) {
		array := value.Interface().(CBORArray)
		writeCBORHead(buffer, 4, uint64(len(array)))
		for index, element := range array {
			if err := encodeCBOR(buffer, reflect.ValueOf(element), depth+1, seen); err != nil {
				return fmt.Errorf("canonical: CBOR array element %d: %w", index, err)
			}
		}
		return nil
	}

	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			buffer.WriteByte(0xf5)
		} else {
			buffer.WriteByte(0xf4)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		writeCBORHead(buffer, 0, value.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := value.Int()
		if integer >= 0 {
			writeCBORHead(buffer, 0, uint64(integer))
		} else {
			// -(integer+1) is safe even for MinInt64.
			writeCBORHead(buffer, 1, uint64(-(integer + 1)))
		}
	case reflect.String:
		text := value.String()
		if !utf8.ValidString(text) {
			return fmt.Errorf("canonical: CBOR text string is not valid UTF-8")
		}
		writeCBORHead(buffer, 3, uint64(len(text)))
		buffer.WriteString(text)
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.IsNil() {
				return fmt.Errorf("canonical: nil CBOR byte string is ambiguous; use an empty slice or null")
			}
			writeCBORHead(buffer, 2, uint64(value.Len()))
			buffer.Write(value.Bytes())
			return nil
		}
		if value.IsNil() {
			return fmt.Errorf("canonical: nil CBOR array is ambiguous; use an empty slice or null")
		}
		writeCBORHead(buffer, 4, uint64(value.Len()))
		for index := 0; index < value.Len(); index++ {
			if err := encodeCBOR(buffer, value.Index(index), depth+1, seen); err != nil {
				return fmt.Errorf("canonical: CBOR array element %d: %w", index, err)
			}
		}
	case reflect.Array:
		// A byte array is a byte string, matching the fixed-size hashes and keys
		// that dominate the ledger schema. Other arrays are CBOR arrays.
		if value.Type().Elem().Kind() == reflect.Uint8 {
			writeCBORHead(buffer, 2, uint64(value.Len()))
			for index := 0; index < value.Len(); index++ {
				buffer.WriteByte(byte(value.Index(index).Uint()))
			}
			return nil
		}
		writeCBORHead(buffer, 4, uint64(value.Len()))
		for index := 0; index < value.Len(); index++ {
			if err := encodeCBOR(buffer, value.Index(index), depth+1, seen); err != nil {
				return fmt.Errorf("canonical: CBOR array element %d: %w", index, err)
			}
		}
	case reflect.Map:
		if value.IsNil() {
			return fmt.Errorf("canonical: nil CBOR map is ambiguous; use an empty map or null")
		}
		entries := make(CBORMap, 0, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			entries = append(entries, CBORMapEntry{
				Key:   iterator.Key().Interface(),
				Value: iterator.Value().Interface(),
			})
		}
		return encodeCBORMap(buffer, entries, depth, seen)
	case reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return fmt.Errorf("canonical: floats and complex numbers are not permitted in CBOR")
	default:
		return fmt.Errorf("canonical: unsupported CBOR Go type %s", value.Type())
	}
	return nil
}

type encodedMapEntry struct {
	key   []byte
	value any
}

func encodeCBORMap(
	buffer *bytes.Buffer,
	entries CBORMap,
	depth int,
	seen map[cborVisit]bool,
) error {
	encoded := make([]encodedMapEntry, len(entries))
	for index, entry := range entries {
		key, err := marshalCBORAtDepth(entry.Key, depth+1, seen)
		if err != nil {
			return fmt.Errorf("canonical: CBOR map key %d: %w", index, err)
		}
		encoded[index] = encodedMapEntry{key: key, value: entry.Value}
	}
	sort.Slice(encoded, func(i, j int) bool {
		return bytes.Compare(encoded[i].key, encoded[j].key) < 0
	})
	for index := 1; index < len(encoded); index++ {
		if bytes.Equal(encoded[index-1].key, encoded[index].key) {
			return fmt.Errorf("canonical: duplicate CBOR map key")
		}
	}

	writeCBORHead(buffer, 5, uint64(len(encoded)))
	for index, entry := range encoded {
		buffer.Write(entry.key)
		if err := encodeCBOR(buffer, reflect.ValueOf(entry.value), depth+1, seen); err != nil {
			return fmt.Errorf("canonical: CBOR map value %d: %w", index, err)
		}
	}
	return nil
}

func marshalCBORAtDepth(
	value any,
	depth int,
	seen map[cborVisit]bool,
) ([]byte, error) {
	var buffer bytes.Buffer
	if err := encodeCBOR(&buffer, reflect.ValueOf(value), depth, seen); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeCBORHead(buffer *bytes.Buffer, major byte, argument uint64) {
	switch {
	case argument < 24:
		buffer.WriteByte((major << 5) | byte(argument))
	case argument <= math.MaxUint8:
		buffer.WriteByte((major << 5) | 24)
		buffer.WriteByte(byte(argument))
	case argument <= math.MaxUint16:
		buffer.WriteByte((major << 5) | 25)
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], uint16(argument))
		buffer.Write(encoded[:])
	case argument <= math.MaxUint32:
		buffer.WriteByte((major << 5) | 26)
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(argument))
		buffer.Write(encoded[:])
	default:
		buffer.WriteByte((major << 5) | 27)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], argument)
		buffer.Write(encoded[:])
	}
}

type cborDecoder struct {
	input  []byte
	offset int
}

func (d *cborDecoder) decode(depth int) (any, error) {
	if depth > MaxCBORDepth {
		return nil, fmt.Errorf("canonical: CBOR nesting exceeds %d", MaxCBORDepth)
	}
	if d.offset >= len(d.input) {
		return nil, fmt.Errorf("canonical: truncated CBOR at byte %d", d.offset)
	}

	initialOffset := d.offset
	initial := d.input[d.offset]
	d.offset++
	major := initial >> 5
	additional := initial & 0x1f

	switch major {
	case 0:
		return d.readArgument(additional, initialOffset)
	case 1:
		argument, err := d.readArgument(additional, initialOffset)
		if err != nil {
			return nil, err
		}
		return CBORNegative(argument), nil
	case 2, 3:
		length, err := d.readArgument(additional, initialOffset)
		if err != nil {
			return nil, err
		}
		if length > uint64(len(d.input)-d.offset) {
			return nil, fmt.Errorf("canonical: truncated CBOR string at byte %d", initialOffset)
		}
		end := d.offset + int(length)
		content := d.input[d.offset:end]
		d.offset = end
		if major == 2 {
			// Preserve the data-model distinction between an empty byte string
			// and null. append([]byte(nil), empty...) yields nil and would make
			// an accepted 0x40 value impossible to re-encode unambiguously.
			copied := make([]byte, len(content))
			copy(copied, content)
			return copied, nil
		}
		if !utf8.Valid(content) {
			return nil, fmt.Errorf("canonical: CBOR text at byte %d is not valid UTF-8", initialOffset)
		}
		return string(content), nil
	case 4:
		length, err := d.readCollectionLength(additional, initialOffset)
		if err != nil {
			return nil, err
		}
		array := make(CBORArray, 0, length)
		for index := 0; index < length; index++ {
			element, err := d.decode(depth + 1)
			if err != nil {
				return nil, fmt.Errorf("canonical: CBOR array element %d: %w", index, err)
			}
			array = append(array, element)
		}
		return array, nil
	case 5:
		length, err := d.readCollectionLength(additional, initialOffset)
		if err != nil {
			return nil, err
		}
		entries := make(CBORMap, 0, length)
		var previousKey []byte
		for index := 0; index < length; index++ {
			keyStart := d.offset
			key, err := d.decode(depth + 1)
			if err != nil {
				return nil, fmt.Errorf("canonical: CBOR map key %d: %w", index, err)
			}
			encodedKey := d.input[keyStart:d.offset]
			if index > 0 && bytes.Compare(previousKey, encodedKey) >= 0 {
				return nil, fmt.Errorf(
					"canonical: CBOR map keys are unsorted or duplicated at entry %d", index,
				)
			}
			previousKey = append(previousKey[:0], encodedKey...)
			value, err := d.decode(depth + 1)
			if err != nil {
				return nil, fmt.Errorf("canonical: CBOR map value %d: %w", index, err)
			}
			entries = append(entries, CBORMapEntry{Key: key, Value: value})
		}
		return entries, nil
	case 6:
		return nil, fmt.Errorf("canonical: CBOR tags are not permitted at byte %d", initialOffset)
	case 7:
		switch additional {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		case 25, 26, 27:
			return nil, fmt.Errorf("canonical: CBOR floats are not permitted at byte %d", initialOffset)
		case 31:
			return nil, fmt.Errorf("canonical: CBOR break/indefinite value is not permitted at byte %d", initialOffset)
		default:
			return nil, fmt.Errorf("canonical: CBOR simple value %d is not permitted at byte %d", additional, initialOffset)
		}
	default:
		panic("unreachable CBOR major type")
	}
}

func (d *cborDecoder) readCollectionLength(additional byte, offset int) (int, error) {
	length, err := d.readArgument(additional, offset)
	if err != nil {
		return 0, err
	}
	// Every item consumes at least one byte. This bound prevents allocation from
	// an attacker-declared length before the decoder discovers truncation.
	if length > uint64(len(d.input)-d.offset) || length > uint64(math.MaxInt) {
		return 0, fmt.Errorf("canonical: impossible CBOR collection length at byte %d", offset)
	}
	return int(length), nil
}

func (d *cborDecoder) readArgument(additional byte, offset int) (uint64, error) {
	switch {
	case additional < 24:
		return uint64(additional), nil
	case additional == 24:
		if d.offset+1 > len(d.input) {
			return 0, fmt.Errorf("canonical: truncated CBOR argument at byte %d", offset)
		}
		value := uint64(d.input[d.offset])
		d.offset++
		if value < 24 {
			return 0, fmt.Errorf("canonical: non-shortest CBOR argument at byte %d", offset)
		}
		return value, nil
	case additional == 25:
		if d.offset+2 > len(d.input) {
			return 0, fmt.Errorf("canonical: truncated CBOR argument at byte %d", offset)
		}
		value := uint64(binary.BigEndian.Uint16(d.input[d.offset : d.offset+2]))
		d.offset += 2
		if value <= math.MaxUint8 {
			return 0, fmt.Errorf("canonical: non-shortest CBOR argument at byte %d", offset)
		}
		return value, nil
	case additional == 26:
		if d.offset+4 > len(d.input) {
			return 0, fmt.Errorf("canonical: truncated CBOR argument at byte %d", offset)
		}
		value := uint64(binary.BigEndian.Uint32(d.input[d.offset : d.offset+4]))
		d.offset += 4
		if value <= math.MaxUint16 {
			return 0, fmt.Errorf("canonical: non-shortest CBOR argument at byte %d", offset)
		}
		return value, nil
	case additional == 27:
		if d.offset+8 > len(d.input) {
			return 0, fmt.Errorf("canonical: truncated CBOR argument at byte %d", offset)
		}
		value := binary.BigEndian.Uint64(d.input[d.offset : d.offset+8])
		d.offset += 8
		if value <= math.MaxUint32 {
			return 0, fmt.Errorf("canonical: non-shortest CBOR argument at byte %d", offset)
		}
		return value, nil
	case additional == 31:
		return 0, fmt.Errorf("canonical: indefinite-length CBOR is not permitted at byte %d", offset)
	default:
		return 0, fmt.Errorf("canonical: reserved CBOR additional information %d at byte %d", additional, offset)
	}
}

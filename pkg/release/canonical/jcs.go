package canonical

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxSafeInteger is 2^53 - 1, the largest integer every conforming JSON
// implementation can represent without loss. The release policy requires any
// integer that can exceed this range to be carried as a canonical base-10
// string, so the canonicalizer rejects bare JSON numbers outside it rather
// than emit bytes a TypeScript or Python reader would round differently.
var maxSafeInteger = big.NewInt(9007199254740991)

// MaxJSONDepth bounds adversarial nesting in canonical JSON and recursive
// traversal of a Go value before marshaling. The release schemas are shallow;
// 64 leaves ample room without making parsers or pointer/container walks a
// stack-exhaustion boundary.
const MaxJSONDepth = 64

var textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()

// Canonicalize rewrites arbitrary UTF-8 JSON into the exact byte sequence the
// release pipeline signs and hashes. It implements RFC 8785 (the JSON
// Canonicalization Scheme) and then enforces the release policy on top:
//
//   - no floating-point numbers, NaN, or infinity;
//   - integers only inside the interoperable range (see maxSafeInteger);
//   - no duplicate object keys;
//   - object keys ordered by their UTF-16 code units;
//   - one value only, with no trailing data.
//
// Insignificant whitespace is removed, strings are minimally escaped per RFC
// 8785, and non-ASCII characters are emitted literally as UTF-8. Canonicalize
// does not perform Unicode normalization: RFC 8785 leaves NFC to the
// application, and schema-level rules police it where required.
func Canonicalize(input []byte) ([]byte, error) {
	if !utf8.Valid(input) {
		return nil, fmt.Errorf("canonical: JSON input is not valid UTF-8")
	}
	if err := validateEscapedUnicode(input); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()

	value, err := readValue(decoder, 0)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("canonical: empty JSON input")
		}
		return nil, err
	}

	// Exactly one value is allowed; anything after it is not canonical input.
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("canonical: trailing data after value: %w", err)
		}
		return nil, fmt.Errorf("canonical: more than one JSON value in input")
	}

	var buffer bytes.Buffer
	writeValue(&buffer, value)
	return buffer.Bytes(), nil
}

// Marshal encodes a Go value and returns its canonical bytes. It is a thin
// composition of encoding/json and Canonicalize, so the release policy applies
// uniformly: a value that marshals to a float or to an out-of-range integer is
// rejected here rather than producing bytes other languages cannot reproduce.
// Fields that must survive as large integers are modeled as canonical base-10
// strings (see Uint64String / BigIntString). Values implementing
// encoding.TextMarshaler are rejected: encoding/json repairs malformed method
// output with U+FFFD, which could collapse distinct inputs to one identity.
// Callers must materialize and validate those values as ordinary strings.
func Marshal(value any) ([]byte, error) {
	// encoding/json replaces malformed UTF-8 in Go strings with U+FFFD. That is
	// convenient for ordinary application JSON but is not acceptable for an
	// identity format: two different malformed byte strings would acquire the
	// same signed bytes. Reject them before encoding instead.
	if err := validateGoStringValues(
		reflect.ValueOf(value),
		map[visit]bool{},
		0,
	); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical: cannot encode value: %w", err)
	}
	return Canonicalize(encoded)
}

// validateEscapedUnicode rejects lone UTF-16 surrogate escapes. Go's JSON
// decoder deliberately replaces them with U+FFFD, while RFC 8785 requires an
// implementation to terminate on malformed Unicode. Raw UTF-8 was validated
// before this scan, so only escaped surrogate pairs need special handling.
func validateEscapedUnicode(input []byte) error {
	for index := 0; index < len(input); index++ {
		if input[index] != '"' {
			continue
		}

		// Scan one JSON string. Structural validity (closing quote, legal escape,
		// and raw control bytes) remains the JSON decoder's job; this pass only
		// handles the Unicode condition the decoder would otherwise repair.
		for index++; index < len(input); index++ {
			switch input[index] {
			case '"':
				goto nextToken
			case '\\':
				if index+1 >= len(input) {
					goto nextToken
				}
				if input[index+1] != 'u' {
					index++
					continue
				}

				codeUnit, ok := parseHexCodeUnit(input, index+2)
				if !ok {
					// The JSON decoder will return the more specific syntax error.
					continue
				}
				if codeUnit >= 0xdc00 && codeUnit <= 0xdfff {
					return fmt.Errorf(
						"canonical: lone low-surrogate escape at byte %d", index,
					)
				}
				if codeUnit >= 0xd800 && codeUnit <= 0xdbff {
					if index+12 > len(input) || input[index+6] != '\\' || input[index+7] != 'u' {
						return fmt.Errorf(
							"canonical: high-surrogate escape at byte %d is not followed by a low surrogate",
							index,
						)
					}
					low, ok := parseHexCodeUnit(input, index+8)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return fmt.Errorf(
							"canonical: high-surrogate escape at byte %d is not followed by a low surrogate",
							index,
						)
					}
					// Skip both six-byte escape sequences; the loop increment lands
					// on the byte after the pair.
					index += 11
					continue
				}
				// Skip this complete \uXXXX sequence.
				index += 5
			}
		}
	nextToken:
	}
	return nil
}

func parseHexCodeUnit(input []byte, start int) (uint16, bool) {
	if start+4 > len(input) {
		return 0, false
	}
	var value uint16
	for _, character := range input[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// visit is the identity used to break pointer/map/slice cycles while walking a
// Go value for invalid strings before encoding/json can replace their bytes.
type visit struct {
	typeOf  reflect.Type
	pointer uintptr
}

func validateGoStringValues(
	value reflect.Value,
	seen map[visit]bool,
	depth int,
) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf(
			"canonical: Go value traversal exceeds %d", MaxJSONDepth,
		)
	}
	if !value.IsValid() {
		return nil
	}

	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		// Interface wrapping is transparent to JSON and cannot form an
		// unbounded chain by itself: assigning one interface to another keeps
		// the concrete dynamic value. Do not make []any consume two depth units
		// per semantic container.
		return validateGoStringValues(value.Elem(), seen, depth)
	}
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return nil
	}
	if value.Type().Implements(textMarshalerType) ||
		(value.Kind() != reflect.Pointer &&
			reflect.PointerTo(value.Type()).Implements(textMarshalerType)) {
		return fmt.Errorf(
			"canonical: Go value type %s implements encoding.TextMarshaler; "+
				"materialize it as a validated string",
			value.Type(),
		)
	}

	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return fmt.Errorf("canonical: Go value contains a string that is not valid UTF-8")
		}
		return nil
	case reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		key := visit{typeOf: value.Type(), pointer: value.Pointer()}
		if seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		return validateGoStringValues(value.Elem(), seen, depth+1)
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		key := visit{typeOf: value.Type(), pointer: value.Pointer()}
		if seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		iterator := value.MapRange()
		for iterator.Next() {
			if err := validateGoStringValues(iterator.Key(), seen, depth+1); err != nil {
				return err
			}
			if err := validateGoStringValues(iterator.Value(), seen, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if value.IsNil() {
			return nil
		}
		key := visit{typeOf: value.Type(), pointer: value.Pointer()}
		if seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		for index := 0; index < value.Len(); index++ {
			if err := validateGoStringValues(value.Index(index), seen, depth+1); err != nil {
				return err
			}
		}
	case reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateGoStringValues(value.Index(index), seen, depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if err := validateGoStringValues(value.Field(index), seen, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// jcsValue is the internal parsed model. Object members are kept as an ordered
// slice so that duplicate-key detection happens before the re-sort, and so the
// re-sort is by UTF-16 code units rather than by Go's native byte order.
type jcsValue interface{ isJCSValue() }

type jcsNull struct{}
type jcsBool bool
type jcsString string

// jcsNumber holds the normalized base-10 form of an in-range integer.
type jcsNumber string

type jcsArray []jcsValue

type jcsMember struct {
	key   string
	value jcsValue
}
type jcsObject []jcsMember

func (jcsNull) isJCSValue()   {}
func (jcsBool) isJCSValue()   {}
func (jcsString) isJCSValue() {}
func (jcsNumber) isJCSValue() {}
func (jcsArray) isJCSValue()  {}
func (jcsObject) isJCSValue() {}

func readValue(decoder *json.Decoder, depth int) (jcsValue, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	switch typed := token.(type) {
	case json.Delim:
		if depth >= MaxJSONDepth {
			return nil, fmt.Errorf(
				"canonical: JSON nesting exceeds %d", MaxJSONDepth,
			)
		}
		switch typed {
		case '{':
			return readObject(decoder, depth+1)
		case '[':
			return readArray(decoder, depth+1)
		default:
			return nil, fmt.Errorf("canonical: unexpected delimiter %q", typed)
		}
	case string:
		return jcsString(typed), nil
	case json.Number:
		return normalizeNumber(typed)
	case bool:
		return jcsBool(typed), nil
	case nil:
		return jcsNull{}, nil
	default:
		return nil, fmt.Errorf("canonical: unsupported token type %T", token)
	}
}

func readObject(decoder *json.Decoder, depth int) (jcsValue, error) {
	members := jcsObject{}
	seen := map[string]struct{}{}

	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("canonical: object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("canonical: duplicate object key %q", key)
		}
		seen[key] = struct{}{}

		value, err := readValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		members = append(members, jcsMember{key: key, value: value})
	}

	// Consume the closing '}'.
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}

	sort.SliceStable(members, func(i, j int) bool {
		return utf16Less(members[i].key, members[j].key)
	})
	return members, nil
}

func readArray(decoder *json.Decoder, depth int) (jcsValue, error) {
	elements := jcsArray{}
	for decoder.More() {
		value, err := readValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		elements = append(elements, value)
	}

	// Consume the closing ']'.
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return elements, nil
}

// normalizeNumber accepts only integers inside the interoperable range and
// returns their canonical base-10 form. Anything with a fraction or exponent
// is a float and is rejected by policy; anything larger than maxSafeInteger
// must be carried as a string instead.
func normalizeNumber(number json.Number) (jcsValue, error) {
	text := string(number)
	if strings.ContainsAny(text, ".eE") {
		return nil, fmt.Errorf(
			"canonical: floating-point numbers are not permitted (%s)",
			text,
		)
	}

	integer, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, fmt.Errorf("canonical: invalid integer %q", text)
	}
	if integer.CmpAbs(maxSafeInteger) > 0 {
		return nil, fmt.Errorf(
			"canonical: integer %s exceeds the interoperable range; "+
				"encode it as a base-10 string",
			text,
		)
	}

	// big.Int.String normalizes representations such as "-0" to "0".
	return jcsNumber(integer.String()), nil
}

func writeValue(buffer *bytes.Buffer, value jcsValue) {
	switch typed := value.(type) {
	case jcsNull:
		buffer.WriteString("null")
	case jcsBool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case jcsNumber:
		buffer.WriteString(string(typed))
	case jcsString:
		writeString(buffer, string(typed))
	case jcsArray:
		buffer.WriteByte('[')
		for index, element := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			writeValue(buffer, element)
		}
		buffer.WriteByte(']')
	case jcsObject:
		buffer.WriteByte('{')
		for index, member := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			writeString(buffer, member.key)
			buffer.WriteByte(':')
			writeValue(buffer, member.value)
		}
		buffer.WriteByte('}')
	}
}

const lowerHex = "0123456789abcdef"

// writeString emits a JSON string using the RFC 8785 escaping rules: escape
// only the two mandatory characters and the C0 control range, using the short
// forms where they exist and lowercase \u00xx otherwise. Every other
// character, including U+007F and all non-ASCII, is written literally as UTF-8.
// This deliberately differs from encoding/json, which also escapes <, >, &,
// U+2028, and U+2029.
func writeString(buffer *bytes.Buffer, value string) {
	buffer.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\t':
			buffer.WriteString(`\t`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\r':
			buffer.WriteString(`\r`)
		default:
			if r < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(lowerHex[(r>>4)&0xf])
				buffer.WriteByte(lowerHex[r&0xf])
			} else {
				buffer.WriteRune(r)
			}
		}
	}
	buffer.WriteByte('"')
}

// utf16Less reports whether a sorts before b when both keys are compared as
// sequences of UTF-16 code units, which is the ordering RFC 8785 mandates for
// object members. For characters outside the Basic Multilingual Plane this
// differs from a raw UTF-8 byte comparison, so the conversion is not optional.
func utf16Less(a, b string) bool {
	unitsA := utf16.Encode([]rune(a))
	unitsB := utf16.Encode([]rune(b))

	for i := 0; i < len(unitsA) && i < len(unitsB); i++ {
		if unitsA[i] != unitsB[i] {
			return unitsA[i] < unitsB[i]
		}
	}
	return len(unitsA) < len(unitsB)
}

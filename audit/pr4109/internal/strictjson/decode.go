// Package strictjson rejects ambiguous JSON before decoding audit records.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Decode decodes exactly one UTF-8 JSON value, rejecting duplicate object
// names, inexact case-folded field aliases, and fields not declared by target.
// encoding/json otherwise silently accepts replacement UTF-8 and the final
// value mapped through either ambiguity, which is unsafe for policy records.
func Decode(data []byte, target any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON input is not valid UTF-8")
	}
	if err := rejectInvalidUnicodeEscapes(data); err != nil {
		return err
	}
	if err := rejectDuplicateNames(data); err != nil {
		return err
	}
	if err := rejectInexactFieldNames(data, target); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectInvalidUnicodeEscapes(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(data) {
				continue
			}
			if data[index+1] != 'u' {
				index++
				continue
			}
			value, ok := unicodeEscapeValue(data, index)
			if !ok {
				continue // The JSON decoder reports malformed hex/length.
			}
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				lowIndex := index + 6
				low, paired := unicodeEscapeValue(data, lowIndex)
				if !paired || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("unpaired high UTF-16 surrogate at byte %d", index)
				}
				index = lowIndex + 5
			case value >= 0xdc00 && value <= 0xdfff:
				return fmt.Errorf("unpaired low UTF-16 surrogate at byte %d", index)
			default:
				index += 5
			}
		}
	}
	return nil
}

func unicodeEscapeValue(data []byte, index int) (uint64, bool) {
	if index+6 > len(data) || data[index] != '\\' || data[index+1] != 'u' {
		return 0, false
	}
	value, err := strconv.ParseUint(string(data[index+2:index+6]), 16, 16)
	return value, err == nil
}

func rejectInexactFieldNames(data []byte, target any) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || targetType.Elem().Kind() == reflect.Invalid {
		return errors.New("JSON decode target must be a nonnil pointer")
	}
	targetValue := reflect.ValueOf(target)
	if targetValue.IsNil() {
		return errors.New("JSON decode target must be a nonnil pointer")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	return validateExactFieldNames(document, targetType.Elem(), "$")
}

func validateExactFieldNames(value any, targetType reflect.Type, path string) error {
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}

	if implementsJSONDecoding(targetType) {
		return nil
	}

	switch targetType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := exactJSONFields(targetType)
		for name, child := range object {
			fieldType, exact := fields[name]
			if !exact {
				for allowed := range fields {
					if strings.EqualFold(name, allowed) {
						return fmt.Errorf(
							"JSON object name %q at %s must use exact field name %q",
							name,
							path,
							allowed,
						)
					}
				}
				continue
			}
			if err := validateExactFieldNames(child, fieldType, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return nil
		}
		for index, child := range array {
			if err := validateExactFieldNames(
				child,
				targetType.Elem(),
				fmt.Sprintf("%s[%d]", path, index),
			); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || targetType.Key().Kind() != reflect.String {
			return nil
		}
		for name, child := range object {
			if err := validateExactFieldNames(
				child,
				targetType.Elem(),
				path+"."+name,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func implementsJSONDecoding(targetType reflect.Type) bool {
	jsonUnmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	return targetType.Implements(jsonUnmarshaler) ||
		reflect.PointerTo(targetType).Implements(jsonUnmarshaler)
}

func exactJSONFields(targetType reflect.Type) map[string]reflect.Type {
	result := make(map[string]reflect.Type)
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}

		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous {
			embeddedType := field.Type
			for embeddedType.Kind() == reflect.Pointer {
				embeddedType = embeddedType.Elem()
			}
			if embeddedType.Kind() == reflect.Struct {
				for embeddedName, embeddedFieldType := range exactJSONFields(embeddedType) {
					result[embeddedName] = embeddedFieldType
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		result[name] = field.Type
	}
	return result
}

func rejectDuplicateNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanValue(decoder, "$"); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return fmt.Errorf("object name at %s is not a string", path)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON object name %q at %s", name, path)
			}
			seen[name] = struct{}{}
			if err := scanValue(decoder, path+"."+name); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("object at %s has invalid closing token %v", path, closing)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("array at %s has invalid closing token %v", path, closing)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
	return nil
}

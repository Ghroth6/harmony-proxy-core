// Package jsonvalue validates bounded JSON before typed decoders can discard
// duplicate fields, nulls or trailing data. Errors contain no private values.
package jsonvalue

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrInvalid = errors.New("JSON_INVALID")
var ErrDuplicate = errors.New("JSON_DUPLICATE")

func Validate(input []byte) error {
	if !validStrings(input) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(input))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return ErrInvalid
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return ErrInvalid
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := make(map[string]bool)
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok {
						return ErrInvalid
					}
					if seen[name] {
						return ErrDuplicate
					}
					seen[name] = true
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return ErrInvalid
				}
			case '[':
				for d.More() {
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

// encoding/json substitutes invalid UTF-8 and lone UTF-16 surrogates. Private
// transport and identity values require rejection before that substitution.
func validStrings(input []byte) bool {
	if !utf8.Valid(input) {
		return false
	}
	inside := false
	for i := 0; i < len(input); i++ {
		if input[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || input[i] != '\\' {
			continue
		}
		i++
		if i >= len(input) {
			return false
		}
		if input[i] != 'u' {
			continue
		}
		value, ok := hexUnit(input, i+1)
		if !ok {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(input) || input[i+1] != '\\' || input[i+2] != 'u' {
			return false
		}
		low, ok := hexUnit(input, i+3)
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inside
}

func hexUnit(input []byte, offset int) (uint16, bool) {
	if offset+4 > len(input) {
		return 0, false
	}
	var value uint16
	for _, b := range input[offset : offset+4] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value |= uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

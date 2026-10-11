package jsonvalue

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// DecodeRequired preserves exact wire presence before encoding/json can infer
// missing false/zero fields or accept case-insensitive names. Only explicitly
// tagged omitempty fields are optional. Validate already rejects all nulls,
// duplicate names, malformed Unicode and trailing documents.
func DecodeRequired(input []byte, target any) error {
	if err := Validate(input); err != nil {
		return err
	}
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return ErrInvalid
	}
	if err := requiredShape(input, typ.Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	return nil
}

func requiredShape(input json.RawMessage, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		return requiredShape(input, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(input, &fields) != nil || fields == nil {
			return ErrInvalid
		}
		known := map[string]bool{}
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tags := strings.Split(field.Tag.Get("json"), ",")
			name := tags[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			known[name] = true
			value, present := fields[name]
			optional := false
			for _, tag := range tags[1:] {
				if tag == "omitempty" {
					optional = true
				}
			}
			if !present {
				if !optional {
					return ErrInvalid
				}
				continue
			}
			if err := requiredShape(value, field.Type); err != nil {
				return err
			}
		}
		for name := range fields {
			if !known[name] {
				return ErrInvalid
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(input, &values) != nil || values == nil {
			return ErrInvalid
		}
		for _, value := range values {
			if err := requiredShape(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

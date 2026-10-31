package config

// MobileValidationError exposes only a stable code and field, never raw parser
// text: native engine errors may contain configuration credentials.
type MobileValidationError struct {
	Code  string
	Field string
	cause error
}

// Existing parsers preserve their normal error text while identifying a safe
// stage/path for the mobile receipt. No error text is sent across the ABI.
type semanticParseError struct {
	code, field string
	cause       error
}

func (e *semanticParseError) Error() string { return e.cause.Error() }
func (e *semanticParseError) Unwrap() error { return e.cause }

func (e *MobileValidationError) Error() string { return e.Code }
func (e *MobileValidationError) Unwrap() error { return e.cause }

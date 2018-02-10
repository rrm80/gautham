package serializer

import (
	"fmt"
)

const (
	// errHeader prefixes all Error strings.
	errHeader = "auth/serializer"

	// efXxx are common error formats used to construct Errors using errorf.
	evInternal    = "(internal) "
	efBadHash     = "%shash #%d not available"
	efBadKeyType  = "%swrong key type; expect (%T)"
	efBadKeyLen   = "%skey length too short; expect min. %s"
	efBadMethod   = "%ssign-method #%d not available for %T"
	efUndefMethod = "%ssign-method #%d not defined"

	// ErrBadFormat is returned during deserialization of a StringToken, if the
	// StringToken does not match the specified format.
	ErrBadFormat = Error("cannot deserialize, malformed input")

	// ErrBadSign is returned if the Signature part of a StringToken does not
	// match the Payload part.
	ErrBadSign = Error("invalid signature")
)

// Error is a generic type implementing the builtin error interface that may be
// returned by a Serializer.
type Error string

// Error implements the builtin error interface.
func (err Error) Error() string {
	return fmt.Sprintf("%s: %s", errHeader, string(err))
}

// errorf formats and returns an Error like fmt.Errorf.
func errorf(f string, v ...interface{}) Error {
	return Error(fmt.Sprintf(f, v...))
}

package token

import (
	"errors"
	"fmt"
)

const (
	tokenErrHeader = "auth/token"
	storeErrHeader = "auth/store"

	evMapSize   = "storage-map size mismatch"
	evMapValues = "cannot parse storage-map values"
)

var (
	// ErrUnregistered may be returned if the record corresponding to a given
	// Token was not found in the storage backend. It may be because the Token
	// was not registered in the first place, or was revoked.
	ErrUnregistered = newStoreError("token not registered; probably revoked")

	// ErrNoBackend is returned if no storage backend is available to a Store.
	ErrNoBackend = newBackendError("not connected to a storage backend")

	// ErrNoSerializer is returned if the Store was (improperly) configured
	// without a serializer.
	ErrNoSerializer = newCodecError("no serializer available")
)

// ValidationError may be returned during processing of a Token if one or more
// of the fields are invalid.
type ValidationError struct {
	errstrs []string
	exp     bool
	nbf     bool
}

// StoreError may be returned during processing of a Token if, for example, a
// storage operation failed.
type StoreError struct {
	errstr         string
	codec, backend bool
}

// StoreHttpError contains within itself a descriptive message as well as HTTP
// status code. If an incoming *http.Request passed to the authorization
// handler could not be authorized, the handler does not write the error
// response to the client itself, but stores the StoreHttpError in the request
// context and passed control to the wrapped handler. The wrapped handler can
// then construct the response from err.Code and err.Message.
type StoreHttpError struct {
	Code    int
	Message string
}

// Error makes StoreError implement the builtin error interface.
func (err *StoreError) Error() string {
	return fmt.Sprintf("%s: %s", storeErrHeader, err.errstr)
}

// IsCodecError returns true if the error originated from an encoding/decoding
// operation by the Store.
func (err *StoreError) IsCodecError() bool { return err.codec }

// IsBackendError return true if the error originated from a store/retrieve
// operation by the Store.
func (err *StoreError) IsBackendError() bool { return err.backend }

// newStoreError constructs and returns a new StoreError.
func newStoreError(errstr string) *StoreError {
	return &StoreError{errstr: errstr}
}

// newBackendError constructs and returns a new StoreError with the backend
// field set to true.
func newBackendError(errstr string) *StoreError {
	return &StoreError{
		errstr:  errstr,
		backend: true,
	}
}

// newCodecError constructs and returns a new CodecError with the codec field
// set to true.
func newCodecError(errstr string) *StoreError {
	return &StoreError{
		errstr: errstr,
		codec:  true,
	}
}

// Error implements the builtin error interface.
func (err *ValidationError) Error() string {
	return tokenErrHeader + ": invalid token"
}

// Errors returns the list of errors embedded in a ValidationError.
func (err *ValidationError) Errors() (errs []error) {
	if 0 == len(err.errstrs) {
		return
	}

	errs = make([]error, len(err.errstrs))
	for i, e := range err.errstrs {
		errs[i] = errors.New(e)
	}

	return
}

// IsExpired returns true if err was caused by a Token that has expired (i.e.
// t.Expires has elapsed).
func (err *ValidationError) IsExpired() bool { return err.exp }

// IsNotBefore returns true if err was caused by a Token that is not yet valid
// (i.e. t.NotBefore has not elpased yet).
func (err *ValidationError) IsNotBefore() bool { return err.nbf }

// append adds an error string to the list of errors embedded inside the
// ValidationError struct.
func (err *ValidationError) append(e string) {
	err.errstrs = append(err.errstrs, e)
}

// Error makes StoreHttpError implement the builtin error interface.
func (err *StoreHttpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", err.Code, err.Message)
}

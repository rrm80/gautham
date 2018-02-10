package token

import (
	"errors"
	"fmt"
)

const (
	tokenErrHeader = "auth/token"
	storeErrHeader = "auth/store"

	evMapSize      = "storage-map size mismatch"
	evMapValues    = "cannot parse storage-map values"
	efBackendError = "backend error (%v)"
	efCodecError   = "encoding/decoding error (%v)"

	// ErrUnregistered may be returned if the record corresponding to a given
	// Token was not found in the storage backend. It may be because the Token
	// was not registered in the first place, or was revoked.
	ErrUnregistered = StoreError("token not registered; probably revoked")

	// ErrNoBackend is returned if no storage backend is available to a Store.
	ErrNoBackend = StoreError("not connected to a storage backend")

	// ErrNoSerializer is returned if the Store was (improperly) configured
	// without a serializer.
	ErrNoSerializer = StoreError("no serializer available")
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
type StoreError string

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

// Error makes StoreError implement the builtin error interface.
func (err StoreError) Error() string {
	return fmt.Sprintf("%s: %s", storeErrHeader, string(err))
}

// storeErrorf formats and returns a StoreError like fmt.Errorf.
func storeErrorf(f string, v ...interface{}) StoreError {
	return StoreError(fmt.Sprintf(f, v...))
}

// Package serializer provides an interface for serializing, deserializing,
// signing and verifying client authorization tokens, as well as some
// implementations of the same.
//
// The name StringToken is used several times throughout the documentation. It
// is not a type or var exported by this package, but is used to refer to the
// final, encoded form of the authorization token that a Serializer operates
// with.
//
// The basic idea of a StringToken, as in use by the implementation of the
// Serializer interface within this package, comes from JSON Web Tokens (RFC
// 7519). But in actual implementation, there are significant differences. A
// StringToken looks like this:
//
//     [Header].[Payload].[Signature]
//
// Like JWT, StringToken has three parts, separated by a single '.' character,
// and like JWT, the Payload and Signature parts are Base64 (url-safe RFC 4648)
// encoded binary chunks. However, unlike JWT, the Header part is a plaintext
// constant string "auth". Other differences that make StringToken completely
// different from and incompatible with JWT, are specified below.
//
// Given a data structure S that is to be used as the payload, in JWT, the
// Payload part is the Base64 encoded form of the JSON encoded S. However, in
// StringToken, the Payload is the Base64 encoded form of the Msgpack encoding
// [1] of S. This is in part due to certain Go implementations of Msgpack being
// magnitudes of order faster [2] and smaller in size as compared to JSON.
//
// The Signature part of a JWT is a cryptographic signature computed from the
// Base64 encoded form of the sequence [Header].[Signature] and then appended
// to the same. However, the Signature part of a StringToken is computed
// directly from the binary (Msgpack encoded) form of Payload. The Payload is
// Base64 encoded, and so is the Signature, and then they are arranged in the
// StringToken format above.
//
// The Signature part of a StringToken is strictly option, but it is highly
// inadvisable to used StringTokens without signature. A StringToken without a
// signature part is perfectly valid as long as the Payload part matches the
// spec.
//
// StringToken is not a standardized, well thought out scheme in any way and in
// fact, any client package can implement the Serializer interface whichever
// way. The specification (if it can even be called that) laid out above is one
// followed by the package-internal implementations of Serializer interface
// that are returned by the NewSerializer function.
//
// Furthermore, the developers of this package have no plans for any promotion,
// advocacy, guaranteed continued support or even standardization of
// StringToken, and using it in production environments that rely on central
// authentication/authorization without having understood all the mechanics and
// concepts involved is highly indvisable, if not outright stupidity.
//
//     [1] https://github.com/msgpack/msgpack/blob/master/spec.md
//     [2] https://github.com/alecthomas/go_serialization_benchmarks/README.md
package serializer

import (
	"crypto"
)

// Different signing methods available for the internal implementation of
// Serializer.
const (
	SignNone  SignMethod = iota
	SignHMAC             // HMAC digest as Signature (see crypto/hmac)
	SignRSA              // RSASSA-PKCS-v1.5 Signature (see crypto/rsa)
	SignPSS              // RSASSA-PSS Signature (see crypto/rsa)
	SignECDSA            // ECDSA Signature (see crypto/ecdsa)
	maxSignMethod

	header = "auth."
)

// Serializer is a type that generates StringTokens from arbitrary Go data
// structures as well as  verifies and unpacks StringTokens to arbitrary Go
// data structures.
type Serializer interface {
	Serialize(token interface{}) (s string, err error)
	Deserialize(s string, token interface{}) (err error)
}

// SignMethod is an enum type used for various methods that the internal
// implementations of Serializer use to computer Signature part of StringToken.
type SignMethod uint

// New returns a Serializer that can generate and parse StringTokens.
//
// method is a SignMethod used to compute Signature part of a StringToken that
// is encoded and appended to the Payload in StringToken. SignNone yields a
// Serializer that omits the Signature part from StringTokens altogether. See
// docs for the SignMethod constants.
//
// key should be a byte-slice of minimum length 256 bytes for SignHMAC, or one
// of *rsa.PrivateKey and *ecdsa.PrivateKey for SignRSA/SignPSS and SignECDSA
// respectvely. An error is returned if the key is not of the expected type.
//
// hash is used to compute a digest of the Payload prior to signing. The
// package corresponding to the selected hash must be imported by the client
// package. See docs for crypto.Hash constants for details.
func New(method SignMethod,
	key interface{}, hash crypto.Hash) (Serializer, error) {

	if !method.isValid() {
		return nil, errorf(efUndefMethod, "", method)
	}

	switch method {
	case SignNone:
		return &genericSerializer{}, nil

	case SignHMAC:
		var ser *hmacSerializer
		var err error

		if ser, err = newHmacSerializer(key, hash); nil != err {
			return nil, err
		}

		return ser, err

	default:
		var ser *cryptoSerializer
		var err error

		if ser, err = newCryptoSerializer(method, key, hash); nil != err {
			return nil, err
		}

		return ser, err
	}
}

// isValid returns true if sm corresponds to one of the valid, available
// signing methods as declared in above contants.
func (sm SignMethod) isValid() bool {
	return sm <= maxSignMethod
}

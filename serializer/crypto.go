package serializer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"runtime"
)

const rsaKeyMinLen = 1024

// cryptoSerializer is an internal implementation of Serializer and may be
// returned by the NewSerializer function. It is a Serializer that uses one
// of the following algorithms to compute Signature from the Payload:
//     - sr.SignMethod == SignRSA   (RSASSA-PKCS1-v1.5)
//     - sr.SignMethod == SignPSS   (RSASSA-PSS)
//     - sr.SignMethod == SignECDSA (ECDSA)
type cryptoSerializer struct {
	SignMethod

	key  crypto.Signer
	hash crypto.Hash
}

// Serialize makes cryptoSerializer implement the Serializer interface.
func (sr *cryptoSerializer) Serialize(
	token interface{}) (s string, err error) {
	return genericSerialize(token, sr.writeSign)
}

// Deserialize makes cryptoSerializer implement the Serializer interface.
func (sr *cryptoSerializer) Deserialize(
	s string, token interface{}) (err error) {
	return genericDeserialize(s, token, sr.compareSign)
}

// newCryptoSerializer returns a new cryptoSerializer struct with the given key
// and hash. The key argument is interface{} so the method can be plug-n-play
// with the newSerializer function, but an error is returned if key is not one
// of *rsa.PrivateKey and *ecdsa.PrivateKey.
func newCryptoSerializer(sm SignMethod,
	key interface{}, hash crypto.Hash) (*cryptoSerializer, error) {

	var ok bool

	if !hash.Available() {
		return nil, errorf(efBadHash, "", hash)
	}

	switch sm {
	case SignRSA, SignPSS:
		var k *rsa.PrivateKey
		if k, ok = key.(*rsa.PrivateKey); !ok {
			return nil, errorf(efBadKeyType, "", k)
		}

		if err := k.Validate(); nil != err {
			return nil, errorf("invalid key (%v)", err)
		}

		if k.N.BitLen() < rsaKeyMinLen {
			return nil, errorf(efBadKeyLen,
				"", fmt.Sprintf("%d bits", rsaKeyMinLen))
		}

		return &cryptoSerializer{sm, k, hash}, nil

	case SignECDSA:
		var k *ecdsa.PrivateKey
		if k, ok = key.(*ecdsa.PrivateKey); !ok {
			return nil, errorf(efBadKeyType, "", k)
		}

		return &cryptoSerializer{sm, k, hash}, nil
	}

	return nil, errorf(efBadMethod, evInternal, sm, &cryptoSerializer{})
}

// writeSign computes the Signature part of StringToken from the binary
// (msgpack encoded) Payload passed as b, and writes the (binary) Signature
// directly to w, returning any error along the way.
func (sr *cryptoSerializer) writeSign(b []byte, w io.Writer) (err error) {
	var dig []byte
	var sig []byte

	// compute the hash digest of binary Payload
	if dig, err = sr.hashDigest(b); nil != err {
		return
	}

	switch sr.SignMethod {
	case SignRSA, SignPSS:
		sig, err = sr.rsaSign(dig)
	case SignECDSA:
		sig, err = sr.ecdsaSign(dig)

	default:
		// should never happen if sr was set up properly
		panic(errorf(efBadMethod, evInternal, sr.SignMethod, sr))
	}

	if nil == err {
		_, err = w.Write(sig)
	}

	return
}

// compareSign takes the (binary) Payload and Signature and compares the
// Signature sig against the Payload b. ErrBadSign may be returned if Signature
// does not match the Payload, otherwise nil is returned.
//
// This method panics if cryptoSerializer was improperly configured.
func (sr *cryptoSerializer) compareSign(b, sig []byte) (err error) {
	var dig []byte

	if dig, err = sr.hashDigest(b); nil != err {
		return
	}

	switch sr.SignMethod {
	case SignRSA, SignPSS:
		return sr.rsaCompare(dig, sig)
	case SignECDSA:
		return sr.ecdsaCompare(dig, sig)
	}

	// should never happen if sr was set up properly
	panic(errorf(efBadMethod, evInternal, sr.SignMethod, sr))
}

// hashDigest computes the hash digest of the binary (msgpack encoded) Payload
// using sr.hash.
func (sr *cryptoSerializer) hashDigest(b []byte) (s []byte, err error) {
	var h = sr.hash.New()
	if _, err = h.Write(b); nil != err {
		return
	}

	return h.Sum(nil), nil
}

// rsaSign computes and returns the bianry Signature sig from the hash digest
// of Payload h using RSASSA-PSS if sr.SignMethod == SignPSS and
// RSASSA-PKCS-v1.5 otherwise.
//
// This method panics if sr.key was not configured properly.
func (sr *cryptoSerializer) rsaSign(h []byte) (sig []byte, err error) {
	defer keyTypeAssertion(&rsa.PrivateKey{})
	var key = sr.key.(*rsa.PrivateKey)

	if sr.SignMethod == SignPSS {
		return rsa.SignPSS(rand.Reader, key, sr.hash, h, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sr.hash,
		})
	}

	return rsa.SignPKCS1v15(rand.Reader, key, sr.hash, h)
}

// rsaCompare verifies the binary Signature sig against the hash digest of
// Payload h using RSASSA-PSS if sr.SignMethod == SignPSS and RSASSA-PKCS-v1.5
// otherwise. nil is returned if Signature matches h, ErrBadSign is returned
// otherwise.
//
// This method panics if sr.key was not configured properly.
func (sr *cryptoSerializer) rsaCompare(h, sig []byte) (err error) {
	defer keyTypeAssertion(&rsa.PrivateKey{})
	var key = &sr.key.(*rsa.PrivateKey).PublicKey

	defer func() {
		if nil != err {
			err = ErrBadSign
		}
	}()

	if sr.SignMethod == SignPSS {
		return rsa.VerifyPSS(key, sr.hash, h, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sr.hash,
		})
	}

	return rsa.VerifyPKCS1v15(key, sr.hash, h, sig)
}

// ecdsaSign computes and returns Signature sig from the hash digest of Payload
// h using ECDSA.
//
// This method panics if sr.key was not configured properly.
func (sr *cryptoSerializer) ecdsaSign(h []byte) (sig []byte, err error) {
	defer keyTypeAssertion(&ecdsa.PrivateKey{})
	var key = sr.key.(*ecdsa.PrivateKey)
	var r, s *big.Int
	var rb, sb []byte

	// n is the size of signature and is 2x byte-length of the key i.e.
	//     2 * (bit-length of key / 8)
	// k marks the middle of the sig buffer
	var n = key.Params().P.BitLen() / 4
	var k = n / 2

	if r, s, err = ecdsa.Sign(rand.Reader, key, h); nil != err {
		return
	}

	rb = r.Bytes()
	sb = s.Bytes()

	// copy rb and sb to sig, such that sig looks like:
	//     [0...][rb]^[0...][sb]
	// where [0...] represents zero-padding in case the byte-length of rb and sb
	// is less than byte-length of the key; and ^ is not an actual byte, just
	// MARKS the middle of sig (k)
	sig = make([]byte, n)
	copy(sig[k-len(rb):], rb)
	copy(sig[n-len(sb):], sb)
	return
}

// rsaCompare verifies the binary Signature sig against the hash digest of
// Payload h using ECDSA. nil is returned if Signature matches h, ErrBadSign is
// returned otherwise.
//
// This method panics if sr.key was not configured properly.
func (sr *cryptoSerializer) ecdsaCompare(h, sig []byte) (err error) {
	defer keyTypeAssertion(&ecdsa.PrivateKey{})
	var key = &sr.key.(*ecdsa.PrivateKey).PublicKey
	var r, s = &big.Int{}, &big.Int{}

	// k is byte-length of the key, as well as 1/2 of expected size of sig
	var k = key.Curve.Params().P.BitLen() / 8

	if len(sig) != 2*k {
		return ErrBadSign
	}

	r, s = r.SetBytes(sig[:k]), s.SetBytes(sig[k:])
	if !ecdsa.Verify(key, h, r, s) {
		return ErrBadSign
	}

	return
}

// keyTypeAssertion is a recovery function that recovers from any
// TypeAssertionError panics inside one of the ^(rsa|ecdsa)(Sign|Compare)$
// methods, and itself panics, but with a more informative error message
// instead of a generic TypeAssertionError.
//
// This function should not be needed if newCryptoSerializer does its job
// properly but still serves as a sanity-check.
func keyTypeAssertion(key crypto.Signer) {
	if r := recover(); nil != r {
		if _, ok := r.(*runtime.TypeAssertionError); ok {
			r = errorf(efBadKeyType, evInternal, key)
		}

		panic(r)
	}
}

package serializer

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"fmt"
	"io"
)

const hmacKeyMinLen = 256

// hmacSerializer is an internal implementation of the Serializer interface and
// may be returned by the NewSerializer function. It is a Serializer that uses
// HMAC to compute Signature from the Payload.
type hmacSerializer struct {
	key  []byte
	hash crypto.Hash
}

// Serialize makes hmacSerializer implement the Serializer interface.
func (sr *hmacSerializer) Serialize(
	token interface{}) (s string, err error) {
	return genericSerialize(token, sr.writeSign)
}

// Deserialize makes hmacSerializer implement the Serializer interface.
func (sr *hmacSerializer) Deserialize(
	s string, token interface{}) (err error) {
	return genericDeserialize(s, token, sr.compareSign)
}

// newHmacSerializer returns a new hmacSerializer struct with the given key and
// hash. The key argument is interface{} so the method can be plug-n-play with
// newSerializer function, but an error is returned if key is not a byte-slice
// of a certain minimum length (256 bytes).
func newHmacSerializer(
	key interface{}, hash crypto.Hash) (*hmacSerializer, error) {

	var k []byte
	var ok bool

	if !hash.Available() {
		return nil, errorf(efBadHash, "", hash)
	}

	if k, ok = key.([]byte); !ok {
		return nil, errorf(efBadKeyType, "", k)
	}

	if len(k) < hmacKeyMinLen {
		return nil, errorf(efBadKeyLen,
			"", fmt.Sprintf("%d bytes", hmacKeyMinLen))
	}

	return &hmacSerializer{k, hash}, nil
}

// writeSign computes the Signature part of StringToken from the binary (msgpack
// encoded) Payload passed as b and writes the (bianry) Signature directly to w,
// returning any error along the way.
func (sr *hmacSerializer) writeSign(b []byte, w io.Writer) (err error) {
	var h = hmac.New(sr.hash.New, sr.key)

	if _, err = h.Write(b); nil != err {
		return
	}

	w.Write(h.Sum(nil))
	return
}

// compareSign takes the (binary) Payload and Signature, recomputes the HMAC
// digest from Payload b and compares the Signature sig against it. ErrBadSign
// is returned if Signature does not match the HMAC digest computed from b or
// nil is returned otherwise.
func (sr *hmacSerializer) compareSign(b, sig []byte) (err error) {
	var buf = bufferPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufferPool.Put(buf) }()

	if err = sr.writeSign(b, buf); nil != err {
		return
	}

	if !bytes.Equal(buf.Bytes(), sig) {
		return ErrBadSign
	}

	return
}

package serializer

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"sync"

	"github.com/vmihailenco/msgpack"
)

// bufferPool is a package global sync.Pool of bytes.Buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// genericSerializer is an internal implementation of the Serializer interface
// that is returned by the NewSerializer function with SignMethod = SignNone.
// This Serializer does not compute the Signature part of StringToken. Instead
// just the Payload part is encoded, appended to Header and returned.
type genericSerializer struct{}

// Serialize makes genericSerializer implement the Serializer interface.
func (sr *genericSerializer) Serialize(
	token interface{}) (s string, err error) {
	return genericSerialize(token, nil)
}

// Deserialize makes genericSerializer implement the Serializer interface.
func (sr *genericSerializer) Deserialize(
	s string, token interface{}) (err error) {
	return genericDeserialize(s, token, nil)
}

// genericSerialize encodes the Payload part of a StringToken and calls the
// writeSign function, if non-nil, to compute the Signature part which is
// appended to the Payload part and returned.
//
// token is msgpack encoded to get the binary form of Payload, which is what is
// used to compute the Signature. The binary forms of Payload and Signature are
// Base64 (url-safe) encoded before being arranged into a StringToken and
// returned.
//
// This function is written such that it can be plugged directly into the
// Serialize method of any of the internal Serializer implementations and only
// the writeSign functions need to be implemented.
func genericSerialize(payload interface{},
	writeSign func([]byte, io.Writer) error) (s string, err error) {

	var buf = bufferPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufferPool.Put(buf) }()

	var b64 = base64.NewEncoder(base64.RawURLEncoding, buf)
	var mpe = msgpack.NewEncoder(buf)
	var pos int

	// binary (msgpack) encode the payload and write to buffer
	if err = mpe.Encode(payload); nil != err {
		return
	}

	// note the position where the binary Payload ends (pos)
	// this position is also where the encoded StringToken begins
	pos = buf.Len()

	// write the Header
	if _, err = buf.WriteString(header); nil != err {
		return
	}

	// Base64 encode PayloadBin and cotinue writing to the buffer following where
	// Header was written
	if _, err = b64.Write(buf.Bytes()[:pos]); nil != err {
		return
	}

	// ensure encoding finishes by calling b64.Close; see docs for base64.Encoder
	if err = b64.Close(); nil != err {
		return
	}

	// if writeSign callback was provided, write the separator, then use the
	// callback to:
	//     - compute Signature using first pos bytes of buffer
	//     - write the Base64 encoded Signature to buffer following the separator
	if nil != writeSign {
		if err = buf.WriteByte('.'); nil != err {
			return
		}

		b64 = base64.NewEncoder(base64.RawURLEncoding, buf)
		if err = writeSign(buf.Bytes()[:pos], b64); nil != err {
			return
		}

		if err = b64.Close(); nil != err {
			return
		}
	}

	// at this point the buffer looks like this:
	//     [PayloadBin][Header].[PayloadB64].[SignatureB64]
	//
	// the first part (PayloadBin) was written and preserved just so Signature
	// could be calculated using that, and is no longer needed; the returned
	// string token starts at Header, to the end of the buffer

	return string(buf.Bytes()[pos:]), nil
}

// genericDeserialize decodes a StringToken, verifying the Signature part by
// calling compareSign, if compareSign is not nil, and unpacking the binary
// (msgpack encoded) Payload to the payload argument.
//
// This function is written such that it can be plugged directly into the
// Deserialize method of any of the internal Serializer implementations and only
// the compareSign functions need to be implemented.
func genericDeserialize(s string, payload interface{},
	compareSign func([]byte, []byte) error) (err error) {

	const H = len(header)

	var i int
	var buf *bytes.Buffer
	var p, sig []byte
	var mpd *msgpack.Decoder
	var wg sync.WaitGroup
	var goB64Decode = func(s string, b *[]byte) {
		defer wg.Done()
		if *b, err = base64.RawURLEncoding.DecodeString(s); nil != err {
			return
		}
	}

	if len(s) <= H || !strings.HasPrefix(s, header) {
		return ErrBadFormat
	}
	s = s[H:]

	// if a compareSign method was not provided, StringToken may not contain
	// the Signature part; so just decode Base64->msgpack->{payload} and return
	if nil == compareSign {
		var b64 io.Reader

		buf = bytes.NewBufferString(s)
		defer func() { buf.Reset(); bufferPool.Put(buf) }()

		b64 = base64.NewDecoder(base64.RawURLEncoding, buf)
		mpd = msgpack.NewDecoder(b64)

		err = mpd.Decode(payload)
		if _, ok := err.(base64.CorruptInputError); ok {
			err = ErrBadFormat
		}

		return
	}

	// if we're here, the StringToken MUST contain a Signature part
	if i = strings.IndexByte(s, '.'); i < 0 || i == len(s)-1 {
		return ErrBadFormat
	}

	// Base64 decode the Payload and Signature part of StringToken concurrently
	wg.Add(2)
	go goB64Decode(s[:i], &p)
	go goB64Decode(s[i+1:], &sig)
	if wg.Wait(); nil != err {
		if _, ok := err.(base64.CorruptInputError); ok {
			return ErrBadFormat
		}

		return
	}

	// once Signature is Base64 decoded, call compareSign to verify the binary
	// Signature against binary Payload
	if err = compareSign(p, sig); nil != err {
		return
	}

	// PERF NOTE:
	// when a bytes.Buffer is constructed from a []byte, the Buffer takes control
	// of the []byte, which means the original alloc for the []byte can be reused
	// with a sync.Pool, reducing load from GC and save memory; BUT... this must
	// not be done unless we are POSITIVE the []byte will not be in use after the
	// function returns
	buf = bytes.NewBuffer(p)
	defer func() { buf.Reset(); bufferPool.Put(buf) }()

	// if Signature checks out, we msgpack decode binary Payload into payload
	mpd = msgpack.NewDecoder(buf)
	err = mpd.Decode(payload)
	return
}

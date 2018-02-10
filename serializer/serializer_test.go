package serializer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack"

	// needed for crypto.SHA256 being used with test Serializers
	_ "crypto/sha256"
)

// tPayloadT is a type for struct payloads.
type tPayloadT struct {
	UUID1 uuid.UUID `msgpack:"id1,omitempty"`
	UUID2 uuid.UUID `msgpack:"id2,omitempty"`
	URI   string    `msgpack:"uri,omitempty"`
	URIS  []string  `msgpack:"urs,omitempty"`
	TS1   int64     `msgpack:"ts1,omitempty"`
	TS2   int64     `msgpack:"ts2,omitempty"`
}

// global test variables
var (
	tPayload  tPayloadT         // _tP is a test payload
	tStrToken string            // _tS is the Msgpack->Base64 encoded form of _tS
	tRandBuf  [512]byte         // _tB is a buffer of random bytes
	tRSAKey   *rsa.PrivateKey   // _kRSA is an RSA key for signing
	tECDSAKey *ecdsa.PrivateKey // _kECDSA is an ECDSA key for signing
)

func init() {

	{ // generate _tP
		tPayload = tPayloadT{
			UUID1: uuid.New(),
			UUID2: uuid.New(),
			URI:   "https://api.example.com",
			URIS: []string{
				"https://app.example.com",
				"https://socket.example.com/auth?foo=bar",
			},
			TS1: time.Now().Unix(),
			TS2: time.Now().Add(7 * 24 * time.Hour).Unix(),
		}
	}

	{ // compute value of _tS
		var b []byte
		var err error
		if b, err = msgpack.Marshal(tPayload); nil != err {
			panic(err)
		}

		tStrToken = base64.RawURLEncoding.EncodeToString(b)
	}

	{ // read random data into _tB
		if _, err := rand.Read(tRandBuf[:]); nil != err {
			panic(err)
		}
	}

	{ // generate an RSA key for _kRSA
		var err error
		if tRSAKey, err = rsa.GenerateKey(rand.Reader, 2048); nil != err {
			panic(err)
		}
	}

	{ // generate an ECDSA key for _kECDSA
		var err error
		if tECDSAKey, err = ecdsa.
			GenerateKey(elliptic.P256(), rand.Reader); nil != err {
			panic(err)
		}
	}
}

func TestNewSerializer(t *testing.T) {
	t.Run("Invalid", func(t *testing.T) {
		if ser, err := New(maxSignMethod+1, nil, 0); nil == err {
			t.Error("expect error for invalid method")
		} else if nil != ser {
			t.Error("expect ser = nil for invalid method")
		}
	})

	t.Run("SignNone", func(t *testing.T) {
		if ser, err := New(SignNone, nil, 0); nil != err {
			t.Error(err)
		} else if _, ok := ser.(*genericSerializer); !ok {
			t.Error("expect ser = genericSerializer{} for method = SignNone")
		}
	})

	t.Run("SignHMAC", func(t *testing.T) {
		var ser Serializer
		var err error

		if ser, err = New(SignHMAC, "", 0); nil == err || nil != ser {
			t.Error("expect error for bad key type")
		}

		if ser, err = New(SignHMAC,
			[]byte("FOO"), 0); nil == err || nil != ser {
			t.Error("expect error for bad key length")
		}

		if ser, err = New(SignHMAC,
			tRandBuf[:256], crypto.RIPEMD160); nil == err || nil != ser {
			t.Error("expect error for unavailbale hash")
		}

		if ser, err = New(SignHMAC,
			tRandBuf[:256], crypto.SHA256); nil != err {
			t.Error(err)
		} else if cser, ok := ser.(*hmacSerializer); !ok {
			t.Error("expect ser = hmacSerializer{...} for method = SignHMAC")
		} else if !reflect.DeepEqual(cser, &hmacSerializer{
			key: tRandBuf[:256], hash: crypto.SHA256}) {
			t.Error("contents of hmacSerializer{...} do not match expectations")
		}
	})

	var cryptoBase = func(t *testing.T,
		m SignMethod, k crypto.Signer) func(t *testing.T) {
		return func(t *testing.T) {
			var ser Serializer
			var err error

			if ser, err = New(m, "", 0); nil == err || nil != ser {
				t.Error("expect error for bad key type")
			}

			if ser, err = New(m,
				k, crypto.RIPEMD160); nil == err || nil != ser {
				t.Error("expect error for unavailable hash")
			}

			if ser, err = New(m, k, crypto.SHA256); nil != err {
				t.Error(err)
			} else if cser, ok := ser.(*cryptoSerializer); !ok {
				t.Error("expect ser = cryptoSerializer{...} for method = SignRSA")
			} else if !reflect.DeepEqual(cser, &cryptoSerializer{
				SignMethod: m, key: k, hash: crypto.SHA256}) {
				t.Error("contents of cryptoSerializer{...} do not match expectation")
			}
		}
	}

	t.Run("SignRSA", cryptoBase(t, SignRSA, tRSAKey))
	t.Run("SignPSS", cryptoBase(t, SignPSS, tRSAKey))
	t.Run("SignECDSA", cryptoBase(t, SignECDSA, tECDSAKey))
}

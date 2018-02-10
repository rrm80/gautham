package serializer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

func TestRSASign(t *testing.T) {
	testCryptoSign(t, &cryptoSerializer{
		SignMethod: SignRSA,
		hash:       crypto.SHA256,
		key:        tRSAKey,
	})

	return
}

func TestPSSSign(t *testing.T) {
	testCryptoSign(t, &cryptoSerializer{
		SignMethod: SignPSS,
		hash:       crypto.SHA256,
		key:        tRSAKey,
	})

	return
}

func TestECDSASign(t *testing.T) {
	testCryptoSign(t, &cryptoSerializer{
		SignMethod: SignECDSA,
		hash:       crypto.SHA256,
		key:        tECDSAKey,
	})

	return
}

func testCryptoSign(t *testing.T, ser *cryptoSerializer) {
	var buf = new(bytes.Buffer)
	var dat = tRandBuf[:256]
	var sN int

	if err := ser.writeSign(dat, buf); nil != err {
		t.Error(err)
	}

	switch ser.key.(type) {
	case *rsa.PrivateKey:
		sN = ser.key.(*rsa.PrivateKey).N.BitLen() / 8
	case *ecdsa.PrivateKey:
		sN = ser.key.(*ecdsa.PrivateKey).Curve.Params().P.BitLen() / 4
	}

	if n := buf.Len(); n != sN {
		t.Errorf("buffer length (%d) does not match expected signature size (%d)",
			n, sN)
	}

	if err := ser.compareSign(dat, buf.Bytes()); nil != err {
		t.Errorf("bad signature written by writeSign (%v)", err)
	}
}

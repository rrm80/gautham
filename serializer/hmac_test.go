package serializer

import (
	"bytes"
	"crypto"
	"testing"
)

func TestHMACSign(t *testing.T) {
	var buf = new(bytes.Buffer)
	var dat = tRandBuf[:256]
	var ser = hmacSerializer{key: tRandBuf[256:], hash: crypto.SHA256}

	if err := ser.writeSign(dat, buf); nil != err {
		t.Error(err)
	}

	if n, k := buf.Len(), ser.hash.Size(); n != k {
		t.Errorf("buffer length (%d) does not match expected signature size (%d)",
			n, k)
	}

	if err := ser.compareSign(dat, buf.Bytes()); nil != err {
		t.Errorf("bad signature written by writeSign (%v)", err)
	}
}

package serializer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"reflect"
	"testing"
)

func TestGenericSerialize(t *testing.T) {
	t.Run("CbNone", func(t *testing.T) {
		if s, err := genericSerialize(tPayload, nil); nil != err {
			t.Error(err)
		} else if exp := header + tStrToken; s != exp {
			t.Errorf("StringToken(returned) != StringToken(expected)"+
				"\nStringToken(returned): %s"+
				"\nStringToken(expected): %s", s, exp)
		}
	})

	t.Run("CbCall", func(t *testing.T) {
		var touched = false
		var cb = func([]byte, io.Writer) error { touched = true; return nil }

		if _, err := genericSerialize(tPayload, cb); nil != err {
			t.Error(err)
		} else if !touched {
			t.Error("writeSign never called by genericSerialize")
		}
	})

	t.Run("CbErr", func(t *testing.T) {
		var cb = func([]byte, io.Writer) error { return Error("") }

		if s, err := genericSerialize(tPayload, cb); nil == err {
			t.Errorf("writeSign error ignored by genericSerialize")
		} else if 0 != len(s) {
			t.Errorf("genericSerialize returned StringToken after writeSign error")
		}
	})

	t.Run("CbWrite", func(t *testing.T) {
		var b [16]byte
		var wb string
		var cb = func(_ []byte, w io.Writer) error {
			w.Write(b[:])
			return nil
		}

		rand.Read(b[:])
		wb = "." + base64.RawURLEncoding.EncodeToString(b[:])

		if s, err := genericSerialize(tPayload, cb); nil != err {
			t.Error(err)
		} else if exp := header + tStrToken + wb; s != exp {
			t.Errorf("writeSign write did not function as expected"+
				"\nStringToken(returned): %s"+
				"\nStringToken(expected): %s", s, exp)
		}
	})
}

func TestGenericDeserialize(t *testing.T) {
	t.Run("CbNone", func(t *testing.T) {
		var p tPayloadT
		if err := genericDeserialize(tStrToken, &p, nil); ErrBadFormat != err {
			t.Error("StringToken format not enforced by genericDeserialize")
		} else if err = genericDeserialize(header+tStrToken, &p, nil); nil != err {
			t.Error(err)
		} else if !reflect.DeepEqual(tPayload, p) {
			t.Error("deserialzed payload does not match expectation")
		}
	})

	t.Run("CbCall", func(t *testing.T) {
		var touched = false
		var p tPayloadT
		var cb = func([]byte, []byte) error { touched = true; return nil }

		if err := genericDeserialize(
			header+tStrToken, &p, cb); ErrBadFormat != err {
			t.Error("StringToken format not enforced with compareSign != nil")
		} else if touched {
			t.Error("compareSign called with wrong StringToken format")
		} else if err = genericDeserialize(
			header+tStrToken+".sig", &p, cb); nil != err {
			t.Error(err)
		} else if !touched {
			t.Error("compareSign never called by genericDeserialize")
		}
	})

	t.Run("CbErr", func(t *testing.T) {
		var p tPayloadT
		var cb = func([]byte, []byte) error { return Error("") }

		if err := genericDeserialize(header+tStrToken, &p, cb); nil == err {
			t.Error("compareSign error ignored by genericDeserialize")
		}

		if !reflect.DeepEqual(p, tPayloadT{}) {
			t.Error("genericDeserialze touched payload after compareSign error")
		}
	})

	t.Run("CbArgs", func(t *testing.T) {
		var p tPayloadT
		var sb [16]byte
		var sg string
		var cb = func(b []byte, sig []byte) error {
			if base64.RawURLEncoding.EncodeToString(b) != tStrToken {
				return Error("args passed to compareSign do not match the payload")
			}
			if !bytes.Equal(sig, sb[:]) {
				return Error("args passed to compareSign do not match the signature")
			}
			return nil
		}

		rand.Read(sb[:])
		sg = "." + base64.RawURLEncoding.EncodeToString(sb[:])

		if err := genericDeserialize(header+tStrToken+sg, &p, cb); nil != err {
			t.Error(err)
		}
	})
}

func BenchmarkGenericSerialize(b *testing.B) {
	var base = func(b *testing.B) {
		if _, err := genericSerialize(tPayload, nil); nil != err {
			b.Fatal(err)
		}
	}

	var conc = func(b *testing.B, p int) func(b *testing.B) {
		return func(b *testing.B) {
			b.SetParallelism(p)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					base(b)
				}
			})
		}
	}

	b.Run("NoConc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			base(b)
		}
	})

	b.Run("LoConc", conc(b, 4))
	b.Run("HiConc", conc(b, 64))
}

func BenchmarkGenericDeserialize(b *testing.B) {
	// s precomputed so string-concatenation does not affect benchmark
	var s = header + tStrToken

	var base = func(b *testing.B) {
		var p tPayloadT
		if err := genericDeserialize(s, &p, nil); nil != err {
			b.Fatal(err)
		}
	}

	var conc = func(b *testing.B, p int) func(b *testing.B) {
		return func(b *testing.B) {
			b.SetParallelism(p)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					base(b)
				}
			})
		}
	}

	b.Run("NoConc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			base(b)
		}
	})

	b.Run("LoConc", conc(b, 4))
	b.Run("HiConc", conc(b, 64))
}

package token

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeStorageKey(t *testing.T) {
	var st Store
	var tk Token
	var u uuid.UUID

	var base = func(st *Store,
		tk *Token, pat bool, exp string) func(*testing.T) {
		return func(t *testing.T) {
			const ef = "st.makeStorageKey did not return expected result" +
				"\nexp: %q" +
				"\nret: %q"

			if r := st.makeStorageKey(tk, pat); r != exp {
				t.Errorf(ef, exp, r)
			}
		}
	}

	// nil *Token always yields key = ""
	t.Run("NoToken", func(t *testing.T) {
		base(&st, nil, false, "")(t)
		base(&st, nil, true, "")(t)
	})

	// general format of the returned key
	t.Run("Typical", func(t *testing.T) {
		base(&st, &tk, false, toB64(u[:])+":"+toB64(u[:]))(t)

		// same as above, just more specific
		tk.Id, tk.Subject = uuid.New(), uuid.New()
		base(&st, &tk, false, toB64(tk.Subject[:])+":"+toB64(tk.Id[:]))
	})

	// namespace is prepended to the key, if available
	// except in case of nil *Token; that always yields key = ""
	t.Run("TypNsp", func(t *testing.T) {

		st.Namespace = "foo"
		base(&st, &tk, false,
			st.Namespace+":"+toB64(tk.Subject[:])+":"+toB64(tk.Id[:]))(t)
		base(&st, nil, false, "")(t)
		base(&st, nil, true, "")(t)
	})

	// p = true yields a key that ends with ":*" instead of tk.Id
	t.Run("Catchall",
		base(&st, &tk, true, st.Namespace+":"+toB64(tk.Subject[:])+":*"))
}

func TestEncStorageData(t *testing.T) {
	var st Store
	var mpNil = [1]byte{0xc0}
	var base = func(name, ret string, exp []byte) {
		const ef = "st.encStorageData did not return expected result [%s]" +
			"\nBase64(exp): %q" +
			"\nBase64(ret): %q"

		if ret != string(exp) {
			t.Errorf(ef, name, toB64(exp), toB64([]byte(ret)))
		}
	}

	// normal case: tk, fpi, fpc are Msgpack encoded forms of Token,
	// Token.fpi and Token.fpc respectively
	t.Run("Typical", func(t *testing.T) {
		if s0, s1, s2, err := st.encStorageData(tToken); nil != err {
			t.Error(err)
		} else {
			base("tk", s0, tTokenBin)
			base("fpi", s1, tFpIBin)
			base("fpc", s2, tFpCBin)
		}
	})

	// atypical case: if Token.fpi or Token.fpc are nil, they are returned
	// encoded as a Msgpack "nil" value (see var mpNil)
	t.Run("NoFp", func(t *testing.T) {
		if _, s1, s2, err := st.encStorageData(&Token{}); nil != err {
			t.Error(err)
		} else {
			base("fpi", s1, mpNil[:])
			base("fpc", s2, mpNil[:])
		}
	})

	// edge case: if Token itself is nil, all of tk, fpi, fpc are Msgpack "nil"
	// values (see var mpNil)
	t.Run("NoToken", func(t *testing.T) {
		if s0, s1, s2, err := st.encStorageData(nil); nil != err {
			t.Error(err)
		} else {
			base("tk", s0, mpNil[:])
			base("fpi", s1, mpNil[:])
			base("fpc", s2, mpNil[:])
		}
	})
}

func TestDecStorageData(t *testing.T) {
	var st Store
	var tc = *tToken
	var mpNil = [1]byte{0xc0}
	var base = func(tk, fpi, fpc []byte, exp *Token) func(*testing.T) {
		return func(t *testing.T) {
			var ef = "st.decStorageData did not return expected result:" +
				"\nexp: %+v" +
				"\nret: %+v"

			if ret, err := st.decStorageData(
				string(tk), string(fpi), string(fpc)); nil != err {
				t.Error(err)
			} else if !reflect.DeepEqual(ret, exp) {
				t.Errorf(ef, exp, ret)
			}
		}
	}

	// normal case: tk, fpi, fpc are decoded into one Token struct, Footprints
	// included
	t.Run("Typical", base(tTokenBin, tFpIBin, tFpCBin, tToken))

	// atypical case: if either fpi or fpc are is or Msgpack "nil" byte, tk.fpi
	// or tk.fpc are set to nil as well, accordingly
	t.Run("NoFp", func(t *testing.T) {
		tc.fpi = tc.fpc
		tc.fpc = nil
		base(tTokenBin, tFpCBin, mpNil[:], &tc)(t)
	})

	// edge case: tk being nil or Msgpack "nil" byte, results yields a nil Token
	// result, regardless of fpi or fpc
	t.Run("NoToken", func(t *testing.T) {
		base(nil, nil, nil, nil)(t)
		base(mpNil[:], nil, tFpCBin, nil)(t)
	})
}

func TestRegisterToken(t *testing.T) {
	skipIfNoRedisClient(t)
	defer redisServer.FlushAll()

	var err error
	var sk string
	var exp time.Duration
	var st = Store{
		redis: redisClient,
	}

	// this function compares what is in the storage backend with precomputed
	// token metadata
	var baseStComp = func(k string, v []byte) {
		const ef = "storage map[%q] does not match expectations:" +
			"\nBase64(exp): %q" +
			"\nBase64(ret): %q"

		if s := redisServer.HGet(sk, k); 0 == len(s) {
			t.Errorf("storage map does not contain key: %q", mapKeys[0])
		} else if s != string(v) {
			t.Errorf(ef, k, toB64(v), toB64([]byte(s)))
		}
	}

	// register token
	if err = st.registerToken(tToken); nil != err {
		t.Fatal(err)
	}

	// the storage key should exist in storage now that token is registered
	sk = st.makeStorageKey(tToken, false)
	if !redisServer.Exists(sk) {
		t.Fatal("token registry key does not exist in storage")
	}

	// compare token metadata with storage map
	baseStComp(mapKeys[0], tTokenBin)
	baseStComp(mapKeys[1], tFpIBin)
	baseStComp(mapKeys[2], tFpCBin)

	// storage key should expire after the token expiry + 5 seconds; (the Expires
	// field of tToken is set to approx. 1 year in the future, see init function;
	// we calculate exp by taking the difference between Unix timestamps - which
	// is in seconds, and then conver it to time.Duration by x-ing with
	// time.Second)
	exp = time.Duration(int64(tToken.Expires)-time.Now().Unix()) * time.Second

	if redisServer.FastForward(exp); !redisServer.Exists(sk) {
		t.Error("storage map expired before the 5sec margin")
	} else if redisServer.FastForward(5 * time.Second); redisServer.Exists(sk) {
		t.Error("storage map did not expire")
	}
}

func TestRetreiveToken(t *testing.T) {
	skipIfNoRedisClient(t)
	defer redisServer.FlushAll()

	const ef = "st.retrieveToken did not return expected result" +
		"\nexp: %+v" +
		"\nret: %+v"
	var st = Store{
		redis: redisClient,
	}

	// should return a nil Token if key does not exist in storage
	if tk, err := st.retrieveToken(
		st.makeStorageKey(tToken, false)); nil != err {
		t.Error(err)
	} else if tk != nil {
		t.Error(ef, nil, tk)
	}

	if err := st.registerToken(tToken); nil != err {
		t.Fatal(err)
	}

	if tk, err := st.retrieveToken(
		st.makeStorageKey(tToken, false)); nil != err {
		t.Error(err)
	} else if !reflect.DeepEqual(tk, tToken) {
		t.Errorf(ef, tToken, tk)
	}
}

func TestAccessToken(t *testing.T) {
	skipIfNoRedisClient(t)
	defer redisServer.FlushAll()

	var tk = *tToken
	var st = Store{
		redis: redisClient,
	}

	var baseFpComp = func(typ string, exp, ret *Footprint) {
		const ef = "st.accessToken does not correctly update %s Footprint:" +
			"\nexp: %+v" +
			"\nret: %+v"
		if !reflect.DeepEqual(exp, ret) {
			t.Errorf(ef, typ, exp, ret)
		}
	}

	// should return ErrUnregistered if Token isn't registered with storage
	if err := st.accessToken(tToken); ErrUnregistered != err {
		t.Fatal(err)
	}

	if err := st.registerToken(tToken); nil != err {
		t.Fatal(err)
	}

	// accessToken should get the initial footprint from storage, decode it and
	// set the fpi field of the passed Token;
	//
	// AND it should also encode the fpc field of passed token and update it in
	// storage
	tk.fpi = nil
	tk.fpc = makeFootprint(0,
		"8.8.8.8", "http://foo.xyz/app", "http://foo.xyz",
		"Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0")

	if err := st.accessToken(&tk); nil != err {
		t.Error(err)
	} else {
		baseFpComp("initial", tToken.fpi, tk.fpi)
	}

	if tj, err := st.retrieveToken(st.makeStorageKey(&tk, false)); nil != err {
		t.Error(err)
	} else {
		baseFpComp("current", tk.fpc, tj.fpc)
	}
}

func TestIssue(t *testing.T) {
	skipIfNoRedisClient(t)
	defer redisServer.FlushAll()

	const efStMap = "st.Issue does not properly set the storage map (%s)"
	const efStEx = "st.Issue does not register token in storage"
	const efSerlr = "st.Issue returned a string that cannot be deserialized: " +
		"(%v)"

	var tk Token
	var sk string
	var st = Store{
		redis: redisClient,
		serlr: tSerlr,
	}

	// st.Issue leaves token Footprints to nil, if supplied Footprint information
	// is empty strings
	if s, err := st.Issue(uuid.New(), 0, "", "", "", ""); nil != err {
		t.Fatal(err)
	} else if err = tSerlr.Deserialize(s, &tk); nil != err {
		t.Errorf(efSerlr, err)
	}

	// storage key should exist (see TestRegisterToken etc.)
	sk = st.makeStorageKey(&tk, false)
	if !redisServer.Exists(sk) {
		t.Fatal(efStEx)
	}

	// values for initial and current Footprints in the storage map should both
	// be Msgpack "nil" values (single byte: 0xc0)
	if fpi, fpc :=
		redisServer.HGet(sk, mapKeys[1]),
		redisServer.HGet(sk, mapKeys[2]); 0 == len(fpi) || 0 == len(fpc) {
		t.Errorf(efStMap, "mssing map key or zero-length value")
	} else if fpi != "\xc0" || fpc != "\xc0" {
		t.Errorf(efStMap, "map value expected to be []byte{0xc0}")
	}

	// issue a new Token, this time with Footprint info
	if s, err := st.Issue(uuid.New(), -1, "10.10.10.10",
		"http://example.org", "http://example.org",
		"Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0",
	); nil != err {
		t.Fatal(err)
	} else if err = tSerlr.Deserialize(s, &tk); nil != err {
		t.Errorf(efSerlr, err)
	}

	// again, storage key should exist
	sk = st.makeStorageKey(&tk, false)
	if !redisServer.Exists(sk) {
		t.Fatal(efStEx)
	}

	// value for current Footprint should be Msgpack "nil" (because Token has not
	// been ts.Access-ed yet) and value for initial Footprint should be something
	// other than Msgpack "nil" value (what exactly it is, is beyond the scope of
	// this test)
	if fpi, fpc :=
		redisServer.HGet(sk, mapKeys[1]),
		redisServer.HGet(sk, mapKeys[2]); 0 == len(fpi) || 0 == len(fpc) {
		t.Errorf(efStMap, "missing map key or zero-length value")
	} else if fpc != "\xc0" {
		t.Errorf(efStMap, "map["+mapKeys[2]+
			"] value expected to be []byte{0xc0}")
	} else if fpi == "\xc0" {
		t.Errorf(efStMap, "map["+mapKeys[1]+
			"] value expected to be something other than []byte{0xc0}")
	}
}

func TestRevoke(t *testing.T) {
	return
}

func TestList(t *testing.T) {
	skipIfNoRedisClient(t)
	defer redisServer.FlushAll()

	var tks = [8]Token{}
	var ret []*Token
	var err error
	var st = Store{
		redis: redisClient,
	}

	// each of tks is a copy of tToken, but with a different t.Id and nil initial
	// and current Footprint components
	for i := 0; i < len(tks); i++ {
		tks[i] = *tToken
		tks[i].Id = uuid.New()
		tks[i].fpi = nil
		tks[i].fpc = nil

		if err = st.registerToken(&tks[i]); nil != err {
			t.Fatal(err)
		}
	}

	// st.List should return a list of all Tokens with the same Subject from the
	// storage
	if ret, err = st.List(&tks[0]); nil != err {
		t.Fatal(err)
	}

	// length of the returned list should be equal to the length of Tokens
	// registered in the first place (tks)
	if n, m := len(ret), len(tks); n != m {
		t.Errorf("st.List did not return expected results: length does not match"+
			"\nlen(exp) = %d"+
			"\nlen(ret) = %d", n, m)
	}

	// for each Token tkx in the returned list, there should be exactly one Token
	// in the original list of registered tokens (tks) that is deep-equal to tkx
	for x, tkx := range ret {
		var found bool

		for y := 0; y < len(tks); y++ {
			var tky = &tks[y]

			if reflect.DeepEqual(tkx, tky) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("st.List ret[%d] does not exist in exp"+
				"\nret[%d]: %+v", x, x, tkx)
		}
	}
}

func BenchmarkEncStorageData(b *testing.B) {
	var st Store
	for i := 0; i < b.N; i++ {
		if _, _, _, err := st.encStorageData(tToken); nil != err {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecStorageData(b *testing.B) {
	var st Store
	var tk, fpi, fpc = string(tTokenBin), string(tFpIBin), string(tFpCBin)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.decStorageData(tk, fpi, fpc); nil != err {
			b.Fatal(err)
		}
	}
}

// toB64 is a helper that converts a given byte-slice to a Base64URL string.
func toB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// skipIfNoRedisClient skips the calling test function if the test-global
// redisClient is nil or not connected to a Redis server (or miniredis inst.)
func skipIfNoRedisClient(t *testing.T) {
	t.Helper()

	const ef = "redisClient not available (%v)"
	if nil == redisClient {
		t.Skipf(ef, redisClient)
	}

	if err := redisClient.Ping().Err(); nil != err {
		t.Skipf(ef, "PING ERR: "+err.Error())
	}
}

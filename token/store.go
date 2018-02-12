package token

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/rrm80/gautham/serializer"
	"github.com/vmihailenco/msgpack"
)

// mapKeys is a list of keys of the stroage map.
var mapKeys = [3]string{"_", "I", "C"}

// mapPool is used to repurpose maps used in redis.HMSet calls.
var mapPool = sync.Pool{
	New: func() interface{} {
		var m = make(map[string]interface{}, len(mapKeys))
		for _, k := range mapKeys {
			m[k] = nil
		}

		return m
	},
}

// bufferPool is used to reuse bytes.Buffers used in msgpack encoding routines.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Store is a service that can issue, parse and keep track of Tokens. It can
// be used to authorize client applications for access to a one or more
// services.
//
// A Store relies on a storage backend to store and keep track of metadata
// relative to each issued Token. A Redis server, or a key-value storage engine
// implementing Redis hash commands and compatible with the Redis protocol
// specifications can be used with a Store.
//
// A Store also needs an implementation of serializer.Serializer for converting
// Token structs to strings that can be effectively used by client applications
// as "bearer" authorization tokens. The serializer package provides some
// passable implementations, any of which can be used with a Store. The
// serialization and signing of Tokens (if applicable) is entirely localized to
// the serializer.Serializer implementation in question, but the metadata of
// the Token that is registered with the storage backend is mostly Msgpack
// encoded.
type Store struct {
	redis *redis.Client
	serlr serializer.Serializer

	// Namespace is used to prefix all storage keys in Redis to prevent collision
	// with other Stores using the same Redis backend.
	Namespace string

	// Issuer identifies this Store while Audience identifies all other services
	// this Store caters to. If any of these fields are present, they are
	// included as part of every Token issued by the Store.
	Issuer   string
	Audience []string

	// DefaultExp is the default expiration time of each Token issued by Store.
	DefaultExp time.Duration
}

// NewStore constructs and returns a new Store with some sane defaults. The
// client and serlr arguments may be nil, but the Store will not perform its
// job without a storage backend, or a serializer. The ConnectStorage and
// UseSerializer methods can be used to later attach a storage backend and a
// serializer, respectively.
func NewStore(client *redis.Client, serlr serializer.Serializer) (st *Store) {
	var b [5]byte
	var nsp = [14]byte{'s', 't', 'o', 'r', 'e', '-'}
	var enc = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769")

	rand.Read(b[:])
	enc.Encode(nsp[6:], b[:])

	// the defaults are:
	//
	// Namespace:   of the format "store-xxxxxxxx" where "xxxxxxxx" is a
	//              randomly generated string of z-base-32 characters
	// DefaultExp:  72 hours

	return &Store{
		redis:      client,
		serlr:      serlr,
		Namespace:  string(nsp[:]),
		DefaultExp: 72 * time.Hour,
	}
}

// ConnectStorage creates a redis.Client using the provided url and tries to
// PING it. If successful, the Store is attached to the storage server
// identified by the url.
func (st *Store) ConnectStorage(url string) (err error) {
	var opts *redis.Options
	var rc *redis.Client

	if opts, err = redis.ParseURL(url); nil != err {
		return
	}

	rc = redis.NewClient(opts)
	if err = rc.Ping().Err(); nil != err {
		return
	}

	st.redis = rc
	return
}

// UseSerializer attempts to create a serializer.Serializer with the given
// parameters (see serializer.New) and if successful, attaches the Serializer
// to Store.
func (st *Store) UseSerializer(
	m serializer.SignMethod, k interface{}, h crypto.Hash) (err error) {
	var ser serializer.Serializer

	if ser, err = serializer.New(m, k, h); nil != err {
		return
	}

	st.serlr = ser
	return
}

// Issue creates a new Token, serializes and registers it with the storage
// backend and returns a string token if successful, that can be passed to
// client applications of use as a "bearer" authorization token.
func (st *Store) Issue(sub uuid.UUID, exp time.Duration,
	remoteAddr, referer, origin, userAgent string) (s string, err error) {

	var t *Token
	var setFpI bool
	var ss = [...]string{remoteAddr, referer, origin, userAgent}

	if nil == st.serlr {
		return "", ErrNoSerializer
	}

	if 0 == exp {
		exp = st.DefaultExp
	}

	if -1 == exp {
		exp = 0
	}

	for _, s := range ss {
		if len(s) != 0 {
			setFpI = true
			break
		}
	}

	t = New(sub, st.Issuer, st.Audience, exp)
	if setFpI {
		t.fpi = makeFootprint(0, ss[0], ss[1], ss[2], ss[3])
	}

	if s, err = st.serlr.Serialize(t); nil != err {
		return "", err
	}

	err = st.registerToken(t)
	return
}

// Access verifies whether a given authorization token s is valid and was
// issued by this Store.
//
// s is deserialized using the attached Serializer and then the storage backend
// is queried for metadata pertaining to the deserialized Token struct. If the
// Token cannot be found in storage, ErrUnregistered is returned and may
// indicate that the Token was revoked. The initial Footprint of the Token is
// returned as part of the returned *Token, and if the Footprint parameters are
// provided, the current Footprint of the *Token is set and updated in storage
// as well.
//
// Access should be used to verify authorization for a client application that
// presented s as the "bearer" authorization token.
func (st *Store) Access(s,
	remoteAddr, referer, origin, userAgent string) (t *Token, err error) {

	var ss = [...]string{remoteAddr, referer, origin, userAgent}
	var setFpC bool

	if nil == st.serlr {
		return nil, ErrNoSerializer
	}

	if err = st.serlr.Deserialize(s, &t); nil != err || nil == t {
		return nil, err
	}

	for _, s := range ss {
		if len(s) != 0 {
			setFpC = true
			break
		}
	}

	if setFpC {
		t.fpc = makeFootprint(0, ss[0], ss[1], ss[2], ss[3])
	}

	if err = st.accessToken(t); nil != err {
		return nil, err
	}

	return
}

// Revoke revokes a Token such that it may not be used by a client application
// to authorize itself anymore.
//
// Revoke removes the metadata pertaining to the given Token from the storage
// backend. If Access is called afterwards with a matching "bearer" token, it
// shall return ErrUnregistered. See Access for details.
func (st *Store) Revoke(t *Token) (err error) {
	var sk string

	if nil == st.redis {
		return ErrNoBackend
	}

	if nil == t {
		return StoreError("nil *Token passed for revokation")
	}

	sk = st.makeStorageKey(t, false)
	if n, err := st.redis.Exists(sk).Result(); nil != err {
		return storeErrorf(efBackendError, err)
	} else if 0 == n {
		return ErrUnregistered
	}

	if err := st.redis.Del(sk).Err(); nil != err {
		return storeErrorf(efBackendError, err)
	}

	return
}

// RevokeN revokes multiple Tokens (see Revoke) as referenced in the given
// argument ts. RevokeN performs the operation concurrently on all provided
// Tokens, and if errors occur during the process, the total number of Tokens
// successfully Revoked, along with only the FIRST encountered error is
// returned.
func (st *Store) RevokeN(ts []*Token) (n int, err error) {
	var ec = make(chan error, len(ts))
	var wg sync.WaitGroup
	var m int32

	if nil == st.redis {
		return 0, ErrNoBackend
	}

	if 0 == len(ts) {
		return
	}

	defer func() { n = int(m) }()

	for _, t := range ts {
		if nil == t {
			continue
		}

		select {
		case err = <-ec:
			return

		default:
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := st.Revoke(t); nil != err {
					if err != ErrUnregistered {
						ec <- err
					}
				}

				atomic.AddInt32(&m, 1)
			}()
		}
	}

	wg.Wait()
	close(ec)

	err, _ = <-ec
	return
}

// List returns a list of Tokens registered with the storage that have the same
// Subject as the given Token t.
//
// The Tokens are reconstructed from the metadata retrieved from storage using
// a key-search, concurrently for all matching Tokens. If errors occur during
// the process, a nil slice is returned along with only the FIRST encountered
// error.
func (st *Store) List(t *Token) (ts []*Token, err error) {

	var ec = make(chan error, 16)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var it *redis.ScanIterator

	if nil == st.redis {
		return nil, ErrNoBackend
	}

	if nil == t {
		return
	}

	for it = st.redis.Scan(0, st.makeStorageKey(t, true), 10).
		Iterator(); it.Next(); {

		select {
		case err = <-ec:
			return

		default:
			wg.Add(1)
			go func() {
				var t *Token
				var err error

				defer wg.Done()
				if t, err = st.retrieveToken(it.Val()); nil != err {
					ec <- err
					return
				}

				if nil != t {
					mu.Lock()
					defer mu.Unlock()
					ts = append(ts, t)
				}
			}()
		}
	}

	if err := it.Err(); nil != err {
		return nil, storeErrorf(efBackendError, err)
	}

	wg.Wait()
	close(ec)

	if err, _ = <-ec; nil != err {
		return nil, err
	}

	return
}

// accessToken fetches the initial Footprint of a Token from the storage
// backend and sets it in the given Token. It also sets the current Footprint
// of the Token as well as updating the same in backend.
func (st *Store) accessToken(t *Token) (err error) {
	var sk string

	// validate the deserialized token, including an nbf check
	if err = t.validate(true); nil != err {
		return
	}

	// retrieve the initial Footprint of Token; if none found, Token was never
	// registered or has been revoked
	sk = st.makeStorageKey(t, false)
	if n, err := st.redis.Exists(sk).Result(); nil != err {
		return storeErrorf(efBackendError, err)
	} else if 0 == n {
		return ErrUnregistered
	}

	if s, err := st.redis.HGet(sk, mapKeys[1]).Result(); nil != err {
		return storeErrorf(efBackendError, err)
	} else if 0 == len(s) {
		return storeErrorf(efBackendError, evMapValues)
	} else if err = msgpack.Unmarshal([]byte(s), &t.fpi); nil != err {
		return storeErrorf(efCodecError, err)
	}

	// store the current Footprint in storage backend
	if fpb, err := msgpack.Marshal(t.fpc); nil != err {
		return storeErrorf(efCodecError, err)
	} else if err = st.redis.HSet(sk, mapKeys[2], fpb).Err(); nil != err {
		return storeErrorf(efBackendError, err)
	}

	return
}

// registerToken stores the metadata of a Token in the storage backend.
func (st *Store) registerToken(t *Token) (err error) {
	var sk string
	var m = mapPool.Get().(map[string]interface{})

	defer func() {
		for _, k := range mapKeys {
			m[k] = nil
		}

		mapPool.Put(m)
	}()

	// validate Token without nbf check
	if err = t.validate(false); nil != err {
		return
	}

	if m[mapKeys[0]], m[mapKeys[1]], m[mapKeys[2]], err =
		st.encStorageData(t); nil != err {
		return err
	}

	sk = st.makeStorageKey(t, false)
	if err := st.redis.HMSet(sk, m).Err(); nil != err {
		return storeErrorf(efBackendError, err)
	}

	if 0 != t.Expires {
		if err := st.redis.ExpireAt(sk, (t.Expires + 5).Time()).Err(); nil != err {
			return storeErrorf(efBackendError, err)
		}
	}

	return
}

// retrieveToken gets the metadata of a Token from the storage backend and
// constructs and returns a Token from the metadata.
func (st *Store) retrieveToken(k string) (t *Token, err error) {
	var sv [len(mapKeys)]string
	var vv []interface{}

	if vv, err = st.redis.HMGet(k, mapKeys[:]...).Result(); nil != err {
		return nil, storeErrorf(efBackendError, err)
	}

	if len(vv) != len(mapKeys[:]) {
		return nil, storeErrorf(efBackendError, evMapSize)
	}

	for i, v := range vv {
		var ok bool

		if nil == v {
			return nil, nil
		}

		if sv[i], ok = v.(string); !ok {
			return nil, storeErrorf(efBackendError, evMapValues)
		}
	}

	return st.decStorageData(sv[0], sv[1], sv[2])
}

// encStorageData converts the token into three binary strings that contain the
// Msgpack encoded metadata of the Token itself. These three components are:
// (a) the Token itself,
// (b) the initial Footprint of the Token and
// (c) the current Footprint of the Token,
// as tk, fpi and fpc respectively.
//
// These strings are stored in the storage backend and used to keep track of
// and verify issued tokens.
func (st *Store) encStorageData(t *Token) (tk, fpi, fpc string, err error) {
	var buf = bufferPool.Get().(*bytes.Buffer)
	var enc = msgpack.NewEncoder(buf)
	defer func() { buf.Reset(); bufferPool.Put(buf) }()

	if nil == t {
		const s = "\xc0"
		return s, s, s, nil
	}

	if err = enc.Encode(t); nil != err {
		return
	}

	tk = buf.String()
	buf.Reset()

	if err = enc.Encode(t.fpi); nil != err {
		return
	}

	fpi = buf.String()
	buf.Reset()

	if err = enc.Encode(t.fpc); nil != err {
		return
	}

	fpc = buf.String()
	return
}

// decStorageData constructs and returns a Token from three binary strings
// containing the Msgpack encoded metadata. For details, see the encStorageData
// method.
func (st *Store) decStorageData(tk, bi, bc string) (t *Token, err error) {
	var buf *bytes.Buffer
	var dec *msgpack.Decoder

	if 0 == len(tk) || "\xc0" == tk {
		return
	}

	buf = bytes.NewBufferString(tk)
	dec = msgpack.NewDecoder(buf)
	defer func() { buf.Reset(); bufferPool.Put(buf) }()
	if err = dec.Decode(&t); nil != err {
		return
	}

	buf.Reset()
	if _, err = buf.WriteString(bi); nil != err {
		return
	}

	if err = dec.Decode(&t.fpi); nil != err {
		return
	}

	buf.Reset()
	if _, err = buf.WriteString(bc); nil != err {
		return
	}

	if err = dec.Decode(&t.fpc); nil != err {
		return
	}

	return
}

// makeStorageKey constructs and returns a string key that can be used to
// identify a Token safely inside the storage backend.
func (st *Store) makeStorageKey(t *Token, p bool) (s string) {
	if nil == t {
		return
	}

	if 0 != len(st.Namespace) {
		s = st.Namespace + ":"
	}

	s += base64.RawURLEncoding.EncodeToString(t.Subject[:]) + ":"

	if p {
		s += "*"
	} else {
		s += base64.RawURLEncoding.EncodeToString(t.Id[:])
	}

	return
}

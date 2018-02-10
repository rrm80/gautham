// Package token implements a token store for tracking client authorization
// tokens.
//
// It also implements a Token struct that can be used in conjunction with a
// Store as a "bearer" authorization token that client applications can use to
// gain authorized access to one or more central services.
package token

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack"
)

// Token is the payload of a token issued by Store and passed around between
// services to authorize access for an entity e.g. a User.
type Token struct {
	// Id and Subjtec identify the Token itself and the entity it was issued for,
	// respectively.
	Id, Subject uuid.UUID

	// Issuer identifies the serivce (Store) that issued the Token. Audience
	// identifies the services that Token is meant to be processed by. Issuer and
	// each member of Audience should be a string URI or IP address.
	Issuer   string
	Audience []string

	// Issued, NotBefore and Expires are times describing the lifetime of the
	// Token. A Token is considered invalid before NotBefore and after Expires.
	Issued, NotBefore, Expires Timestamp

	// fpi is the Footprint of the Token when it was issued.
	// fpc is the Footprint of the Token when it was last verified by a
	// Store.
	fpi, fpc *Footprint
}

// token is the internal representation of a Token struct. It is used to
// convert Token to and from its Msgpack representation.
type token struct {
	Id        []byte `msgpack:"tid"`
	Subject   []byte `msgpack:"sub"`
	Issuer    string `msgpack:"iss,omitempty"`
	Audience  string `msgpack:"aud,omitempty"`
	Issued    int64  `msgpack:"iat"`
	NotBefore int64  `msgpack:"nbf,omitempty"`
	Expires   int64  `msgpack:"exp,omitempty"`
}

// Footprint returns the two Footprint structs associated with the Token.
// The first Footprint (fpi) is the Footprint at the time Token was issued and
// the second Footprint (fpc) is the Footprint at the time Token was last
// verified by a Store.
func (t *Token) Footprint() (fpi, fpc *Footprint) {
	return t.fpi, t.fpc
}

// EncodeMsgpack implements the msgpack.CustomEncoder interface.
func (t *Token) EncodeMsgpack(e *msgpack.Encoder) (err error) {
	return e.Encode(t.toInternal())
}

// DecodeMsgpack implements the msgpack.CustomDecoder interface.
func (t *Token) DecodeMsgpack(d *msgpack.Decoder) (err error) {
	var _t token
	if err = d.Decode(&_t); nil != err {
		return
	}

	t.fromInternal(&_t)
	return
}

// New constructs a new Token from the given values. t.Id is set to a newly
// generated UUIDv4 (see uuid.NewRandom) and t.Issued is set to the current
// Unix time.
func New(sub uuid.UUID,
	iss string, aud []string, exp time.Duration) (t *Token) {

	t = &Token{
		Id:       uuid.New(),
		Subject:  sub,
		Issuer:   iss,
		Audience: aud,
		Issued:   Timestamp(time.Now().Unix()),
	}

	if 0 != exp {
		t.Expires = Timestamp(time.Now().Add(exp).Unix())
	}

	return
}

// toInternal converts Token to its internal representation (token).
func (t *Token) toInternal() (_t *token) {
	var z uuid.UUID

	_t = &token{
		Issuer:    t.Issuer,
		Audience:  strings.Join(t.Audience, "\x00"),
		Issued:    int64(t.Issued),
		NotBefore: int64(t.NotBefore),
		Expires:   int64(t.Expires),
	}

	if u := t.Id[:]; !bytes.Equal(u, z[:]) {
		_t.Id = u
	}

	if u := t.Subject[:]; !bytes.Equal(u, z[:]) {
		_t.Subject = u
	}

	return
}

// fromInternal fills up a Token from its internal representation (token).
func (t *Token) fromInternal(_t *token) {
	var z uuid.UUID
	*t = Token{}

	if nil == _t {
		return
	}

	t.Issuer, t.Issued, t.NotBefore, t.Expires = _t.Issuer,
		Timestamp(_t.Issued), Timestamp(_t.NotBefore), Timestamp(_t.Expires)

	if 0 != len(_t.Audience) {
		t.Audience = strings.Split(_t.Audience, "\x00")
	}

	if len(z) == len(_t.Id) {
		copy(t.Id[:], _t.Id)
	}

	if len(z) == len(_t.Subject) {
		copy(t.Subject[:], _t.Subject)
	}

	return
}

// validate validates the fields of Token.
func (t *Token) validate(nbfCheck bool) (err error) {
	var zu = uuid.UUID{}
	var ve = &ValidationError{}
	var now = Timestamp(time.Now().Unix())

	if bytes.Equal(zu[:], t.Id[:]) {
		ve.append("Token.Id is invalid (zero-UUID)")
	}

	if bytes.Equal(zu[:], t.Subject[:]) {
		ve.append("Token.Subject is invalid (zero-UUID)")
	}

	if 0 == t.Issued {
		ve.append("Token.Issued is invalid (zero-Timestamp)")
	} else if t.Issued > now {
		ve.append("Token.Issued is > time.Now()")
	}

	if t.Expires != 0 && t.Expires < (now+5) {
		ve.append(fmt.Sprintf(
			"Token.Expires is < time.Now(); expired %v",
			t.Expires.Time().String()))
		ve.exp = true
	}

	if nbfCheck &&
		t.NotBefore != 0 &&
		int64(t.NotBefore) > (time.Now().Unix()-5) {
		ve.append(fmt.Sprintf(
			"Token.NotBefore is < time.Now(); not before %v",
			t.Expires.Time().String()))
		ve.nbf = true
	}

	if 0 != len(ve.errstrs) || ve.exp || ve.nbf {
		err = ve
	}

	return
}

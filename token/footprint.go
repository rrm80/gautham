package token

import (
	"net"
	"strings"
	"time"

	"github.com/ua-parser/uap-go/uaparser"
	"github.com/vmihailenco/msgpack"
)

var uaParser = uaparser.NewFromSaved()

// Timestamp wraps a primitive int64 representing the number of SECONDS since
// the Unix epoch (POSIX time) and provides a method ts.Time for converting
// Timestamp back into Go time.Time struct.
//
// Timestamp is used instead of time.Time in Token and Footprint because it is
// slightly more convenient to compare Timestamps or check for mutated state or
// validity of a timestamp field within either of those structs.
type Timestamp int64

// Time returns the time.Time struct corresponding to the Timestamp value.
func (ts Timestamp) Time() time.Time { return time.Unix(int64(ts), 0) }

// Footprint represents the digital footprint of a Token, i.e. the
// characterstics of the remote node or application which the Token was
// originally issued for or was accessed by.
//
// The Footprint of a Token is constructed by the Store during a st.Issue or
// st.Verify call, using the parameters supplied by the caller. The Store then
// uses the Footprints to keep track of Tokens.
type Footprint struct {
	Timestamp  Timestamp
	RemoteAddr net.IP

	Referer, Origin string

	UserAgent *uaparser.UserAgent
	Os        *uaparser.Os
	Device    *uaparser.Device
}

// footprint is the internal representation of a Footprint struct, mainly used
// for conversion to and from its Msgpack representation. It maps all exported
// fields of the Footprint struct to primitive types to keep the Msgpack
// representation as compact and efficient as possible.
type footprint struct {
	Timestamp  int64  `msgpack:"tsp,omitempty"`
	RemoteAddr []byte `msgpack:"adr,omitempty"`
	Referer    string `msgpack:"ref,omitempty"`
	Origin     string `msgpack:"org,omitempty"`
	UserAgent  string `msgpack:"uag,omitempty"`
	Os         string `msgpack:"uos,omitempty"`
	Device     string `msgpack:"udv,omitempty"`
}

// EncodeMsgpack implements the msgpack.CustomEncoder interface for easy and
// fast conversion of a Footprint to its custom Msgpack representation.
func (fp *Footprint) EncodeMsgpack(e *msgpack.Encoder) (err error) {
	return e.Encode(fp.toInternal())
}

// DecodeMsgpack implements the msgpack.CustomDecoder interface for easy and
// fast conversion of a custom encoded Msgpack representation to Footprint.
func (fp *Footprint) DecodeMsgpack(d *msgpack.Decoder) (err error) {
	var _fp footprint
	if err = d.Decode(&_fp); nil != err {
		return
	}

	fp.fromInternal(&_fp)
	return
}

// makeFootprint constructs and returns a Footprint by parsing the given args.
func makeFootprint(ts int64, addr, refr, orig, uags string) (fp *Footprint) {

	fp = &Footprint{Referer: refr, Origin: orig}

	if 0 == ts {
		fp.Timestamp = Timestamp(time.Now().Unix())
	} else {
		fp.Timestamp = Timestamp(ts)
	}

	if 0 != len(addr) {
		var ip = net.ParseIP(addr)
		if nil == ip {
			return nil
		}

		fp.RemoteAddr = ip
	}

	if 0 != len(uags) {
		var c = uaParser.Parse(uags)
		if nil != c {
			fp.UserAgent, fp.Os, fp.Device = c.UserAgent, c.Os, c.Device
		}
	}

	return
}

// toInternal converts a Footprint to its internal representation footprint and
// is mainly used for Msgpack encoding a Footprint struct. The fp.Timestamp,
// fp.RemoteAddr, fp.Referer and fp.Origin fields are just type cast where
// applicable, but the fp.UserAgent, fp.Os and fp.Device fields are converted
// by encoding the uaparser.UserAgent, uaparser.Os and uaparser.Device structs
// to a null-separated list of field values.
func (fp *Footprint) toInternal() (_fp *footprint) {
	_fp = &footprint{
		Referer:   fp.Referer,
		Origin:    fp.Origin,
		Timestamp: int64(fp.Timestamp),
	}

	if 0 != len(fp.RemoteAddr) {
		_fp.RemoteAddr = fp.RemoteAddr[:]
	}

	if ua := fp.UserAgent; nil != ua {
		_fp.UserAgent = strings.Join([]string{
			ua.Family, ua.Major, ua.Minor, ua.Patch,
		}, "\x00")
	}

	if os := fp.Os; nil != os {
		_fp.Os = strings.Join([]string{
			os.Family, os.Major, os.Minor, os.Patch, os.PatchMinor,
		}, "\x00")
	}

	if dv := fp.Device; nil != dv {
		_fp.Device = strings.Join([]string{
			dv.Brand, dv.Family, dv.Model,
		}, "\x00")
	}

	return
}

// fromInternal fills a Footprint from its internal representation footprint.
// It is mainly used for Msgpack decoding a properly encoded Footprint struct.
// The fp.Timestamp, fp.RemoteAddr, fp.Referer and fp.Origin fields are simply
// obtained by type cast where applicable. The fp.UserAgent, fp.Os, fp.Device
// fields are obtained by decoding values as a string separating field values
// by a null char.
func (fp *Footprint) fromInternal(_fp *footprint) {
	*fp = Footprint{}

	if nil == _fp {
		return
	}

	fp.Referer, fp.Origin, fp.Timestamp =
		_fp.Referer, _fp.Origin, Timestamp(_fp.Timestamp)

	if 0 != len(_fp.RemoteAddr) {
		fp.RemoteAddr = net.IP(_fp.RemoteAddr)
	}

	if 0 != len(_fp.UserAgent) {
		var ua [4]string
		copy(ua[:], strings.Split(_fp.UserAgent, "\x00"))

		fp.UserAgent = &uaparser.UserAgent{
			Family: ua[0],
			Major:  ua[1],
			Minor:  ua[2],
			Patch:  ua[3],
		}
	}

	if 0 != len(_fp.Os) {
		var os [5]string
		copy(os[:], strings.Split(_fp.Os, "\x00"))

		fp.Os = &uaparser.Os{
			Family:     os[0],
			Major:      os[1],
			Minor:      os[2],
			Patch:      os[3],
			PatchMinor: os[4],
		}
	}

	if 0 != len(_fp.Device) {
		var dv [3]string
		copy(dv[:], strings.Split(_fp.Device, "\x00"))

		fp.Device = &uaparser.Device{
			Brand:  dv[0],
			Family: dv[1],
			Model:  dv[2],
		}
	}
}

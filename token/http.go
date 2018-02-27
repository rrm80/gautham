package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// AuthorizeHandler returns a http.Handler (outside handler) that wraps the
// given http.Handler (inside handler) within itself.
//
// The outside handler checks the "Authorization" HTTP header on the incoming
// request, and tries to parse and verify the encoded string-token contained
// within the header value before invoking the inside handler.
//
// The Authorized method of the same Store instance can be used within the
// inside handler to retrieve the result of the authorization process.
func (st *Store) AuthorizeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t, err := st.processAuthHeader(r); nil != err {
			w.Header().Set("Authorization", r.Header.Get("Authorization"))
			h.ServeHTTP(w, st.setCtxErr(r, err))
		} else {
			h.ServeHTTP(w, st.setCtxToken(r, t))
		}

		return
	})
}

// Authorized checks if a given request has been processed by AuthorizeHandler
// and returns the Token or error resulting from the authorization process.
func (st *Store) Authorized(r *http.Request) (t *Token, err error) {
	var v = r.Context().Value(st.ctxKey)
	var ok bool

	if nil == v {
		return nil, errors.New("Authorization Unknown/Not Processed")
	}

	if t, ok = v.(*Token); ok {
		return
	}

	if err, ok = v.(error); ok {
		return
	}

	return
}

// processAuthHeader processes the "Authorize" header of the given request,
// passing the authorization token from the header to the Access function of
// the receiving Store, returning a Token if the request is authorized and
// an error otherwise. The returned error may be a StoreHttpError with a
// contextually appropriate HTTP status code.
func (st *Store) processAuthHeader(r *http.Request) (t *Token, err error) {
	var s string

	if a, b := nil == st.serlr, nil == st.redis; a || b {
		const baseErrstr = "Service Unavailable"
		var stErr = &StoreHttpError{Code: http.StatusServiceUnavailable}

		if b {
			stErr.Message = fmt.Sprintf("%s (Auth/%s)", baseErrstr, "Storage")
		} else if a {
			stErr.Message = fmt.Sprintf("%s (Auth/%s)", baseErrstr, "Serializer")
		}

		return nil, stErr
	}

	s = r.Header.Get("Authorization")
	if 0 == len(s) {
		return nil, errors.New(`No "Authorization" Header`)
	}

	if len(s) <= 7 || s[:7] != "Bearer " {
		return nil, errors.New(`Malformed "Authorization" Header`)
	}

	s = s[7:]

	// IMPORTANT NOTE:
	// r.RemoteAddr, r.Referer(), r.UserAgent() and the "Origin" header on the
	// underlying *http.Request is used directly to verify the Token; this may
	// cause issues behind proxies, for example, the RemoteAddr prop of the
	// *http.Request may reflect the address of the proxy server, instead of
	// the actual client address;
	// futher processing may be required by a wrapping handler (for example,
	// parse the X-Forwarded-For, or X-Real-IP etc. header of the incoming
	// request, and replace the r.RemoteAddr with the correct client address)
	if t, err = st.Access(s, r.RemoteAddr, r.Referer(), r.Header.Get("Origin"),
		r.UserAgent()); nil == err {
		return
	}

	if err == ErrUnregistered {
		return nil, errors.New("Authorization Token Revoked, Unregistered")
	}

	if e, ok := err.(*ValidationError); ok {
		const ef = "Authorization Token %s"
		if e.exp {
			err = fmt.Errorf(ef, "Expired")
		} else if e.nbf {
			err = fmt.Errorf(ef, "Used Before NBF")
		} else {
			err = fmt.Errorf(ef, "Invalid (Internal/Undisclosed)")
		}

		return
	}

	if e, ok := err.(*StoreError); ok {
		var err = &StoreHttpError{Code: http.StatusInternalServerError}
		if e.codec {
			return nil, fmt.Errorf("Bad Authorization (%s)", e.errstr)
		}

		if e.backend {
			err.Message = fmt.Sprintf("Storage Error (%s)", e.errstr)
		} else {
			err.Message = fmt.Sprintf("Internal Error (%s)", e.errstr)
		}

		return nil, err
	}

	return
}

// setCtxErr returns a shallow copy of the given http.Request with a context
// that contains the given error as value associated with st.ctxKey used as the
// map key.
func (st *Store) setCtxErr(r *http.Request, err error) *http.Request {
	if nil == r || nil == err {
		return r
	}

	if _, ok := err.(*StoreHttpError); !ok {
		err = &StoreHttpError{Code: http.StatusUnauthorized, Message: err.Error()}
	}

	return r.WithContext(context.WithValue(r.Context(), st.ctxKey, err))
}

// setCtxErr returns a shallow copy of the given http.Request with a context
// that contains the given Token as value associated with st.ctxKey used as the
// map key.
func (st *Store) setCtxToken(r *http.Request, t *Token) *http.Request {
	if nil == r || nil == t {
		return r
	}

	return r.WithContext(context.WithValue(r.Context(), st.ctxKey, t))
}

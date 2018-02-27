package token

import (
	"encoding/json"
	"net/http"
	// for crypto.SHA256 implementation
	_ "crypto/sha256"
)

func ExampleStore_AuthorizeHandler() {
	var store *Store
	var mx = http.NewServeMux()
	var authMx http.Handler

	// store does not have a backend or serializer available, and will return
	// errors when asked to issue or verify a token-string. See NewStore,
	// store.ConnectStroage and store.UseSerializer functions for details.
	store = NewStore(nil, nil)

	// GET / will respond with "Hello, Authorized!" if the incoming request
	// carried a valid token in the Authorization header, and an HTTP error
	// status code and message otherwise.
	mx.Handle("/",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := store.Authorized(r); nil != err {
				var statusCode int

				if e, ok := err.(*StoreHttpError); ok {
					statusCode = e.Code
				} else {
					statusCode = http.StatusInternalServerError
				}

				w.WriteHeader(statusCode)
				w.Write([]byte(err.Error()))
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, Authorized!"))
		}))

	// GET /echo will respond with the JSON formatted parsed Token, or a simple
	// JSON error object otherwise.
	mx.Handle("/auth",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var errorResponse struct {
				Status  int    `json:"status"`
				Message string `json:"message"`
			}

			var jsonEncoder = json.NewEncoder(w)

			if t, err := store.Authorized(r); nil != err {
				if e, ok := err.(*StoreHttpError); ok {
					errorResponse.Status = e.Code
					errorResponse.Message = e.Message
				} else {
					errorResponse.Status = http.StatusInternalServerError
					errorResponse.Message = err.Error()
				}

				w.WriteHeader(errorResponse.Status)
				jsonEncoder.Encode(errorResponse)
			} else {
				w.WriteHeader(http.StatusOK)
				jsonEncoder.Encode(t)
			}
		}))

	// authMx wraps mx such that every incoming request is processed by hdlr
	// before being passed on to mx for further processing.
	//
	// authMx will parse the "Authorization" header, verify any token present and
	// store the result in a context.Context which is later retrieved inside mx
	// using the store.Authorized function.
	authMx = store.AuthorizeHandler(mx)

	if err := http.ListenAndServe(":3331", authMx); nil != err {
		panic(err)
	}

	// ...
}

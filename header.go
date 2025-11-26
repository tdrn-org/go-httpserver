//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"net"
	"net/http"
)

// Header interface is used to apply response headers during http
// request processing.
type Header interface {
	// Apply is invoked during http processing to add response headers.
	Apply(w http.ResponseWriter, r *http.Request)
}

// HeaderFunc defines the function based Header interface.
type HeaderFunc func(w http.ResponseWriter, r *http.Request)

// Apply is invoked during http processing to add response headers.
func (f HeaderFunc) Apply(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}

// StaticHeader creates a Header instance setting a single
// static header.
func StaticHeader(key string, value string) HeaderFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add(key, value)
	}
}

// WithHeaders defines the Header instances to apply during
// http request processing.
func WithHeaders(headers ...Header) ServerOptionFunc {
	return func(server *Instance, _ *net.ListenConfig) {
		server.headers = headers
	}
}

func enableHeaders(server *Instance) {
	if server.headers != nil {
		server.httpServer.Handler = &headerHandler{
			handler: server.httpServer.Handler,
			headers: server.headers,
		}
	}
}

type headerHandler struct {
	handler http.Handler
	headers []Header
}

func (h *headerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, header := range h.headers {
		header.Apply(w, r)
	}
	h.handler.ServeHTTP(w, r)
}

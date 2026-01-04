//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

const testHeaderKey string = "X-Test"
const testHeaderValue string = "test"

var testHeader httpserver.Header = httpserver.StaticHeader(testHeaderKey, testHeaderValue)

func TestWithHeaders(t *testing.T) {
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithHeaders(testHeader),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := http.Get(server.BaseURL().JoinPath(headerPath).String())
		require.NoError(t, err)
		defer status.Body.Close()
		require.Equal(t, testHeaderValue, status.Header.Get(testHeaderKey))
		require.Equal(t, http.StatusOK, status.StatusCode)
	}, options...)
}

func TestHeaderHandler(t *testing.T) {
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		path := "/test_header_handler"
		server.HandleFunc(path, httpserver.HeaderHandlerFunc(handleNoop, testHeader))
		status, err := http.Get(server.BaseURL().JoinPath(path).String())
		require.NoError(t, err)
		defer status.Body.Close()
		require.Equal(t, testHeaderValue, status.Header.Get(testHeaderKey))
		require.Equal(t, http.StatusOK, status.StatusCode)
	})
}

//
// Copyright (C) 2025 Holger de Carne
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

const dummyHeaderKey string = "X-Dummy"
const dummyHeaderValue string = "dummy"

func TestWithHeaders(t *testing.T) {
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithHeaders(httpserver.StaticHeader(dummyHeaderKey, dummyHeaderValue)),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := http.Get(server.BaseURL().JoinPath(headerPath).String())
		require.NoError(t, err)
		defer status.Body.Close()
		require.Equal(t, dummyHeaderValue, status.Header.Get(dummyHeaderKey))
		require.Equal(t, http.StatusOK, status.StatusCode)
	}, options...)
}

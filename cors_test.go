//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/rs/cors"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

func TestCors(t *testing.T) {
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithCorsOptions(&cors.Options{}),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, statusCode)
	}, options...)
}

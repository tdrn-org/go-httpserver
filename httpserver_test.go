//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/rs/cors"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

func TestListenTCPLocalhost(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "tcp", "localhost:0")
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

func TestListenTCPAny(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

func TestListenUnix(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "TestListenUnix.sock"))
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

func TestMustListen(t *testing.T) {
	require.Panics(t, func() {
		httpserver.MustListen(t.Context(), "tcp", "localhost:-1")
	})
}

func TestPing(t *testing.T) {
	options := []httpserver.ServerOption{
		httpserver.WithAccessLog(slog.Default()),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}, options...)
}

func TestTrustedProxyPolicy(t *testing.T) {
	networks, err := httpserver.ParseNetworks("10.0.0.0/8")
	require.NoError(t, err)
	trustedProxyPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedProxyPolicy(trustedProxyPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, status)
	}, options...)
}

func TestCors(t *testing.T) {
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithCorsOptions(&cors.Options{}),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}, options...)
}

func runServerTest(t *testing.T, test func(*testing.T, *httpserver.Instance), options ...httpserver.ServerOption) {
	server, err := httpserver.Listen(t.Context(), "tcp", "localhost:0", options...)
	require.NoError(t, err)
	require.NotNil(t, server)
	server.HandleFunc("/", handlePing)
	go func() {
		err := server.Serve()
		if !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	}()
	test(t, server)
	err = server.Shutdown(t.Context())
	require.NoError(t, err)
	err = server.Close()
	require.NoError(t, err)
}

func handlePing(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/rs/cors"
	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

const remoteIPHeader string = "X-Remote-IP"

var remoteIP1234 net.IP = net.ParseIP("1.2.3.4")

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
		httpserver.WithDefaultAccessLog(),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}, options...)
}

func TestRemoteIP(t *testing.T) {
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedHeaders(remoteIPHeader),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		req, err := http.NewRequest(http.MethodGet, server.BaseURL().JoinPath("/remoteip").String(), nil)
		require.NoError(t, err)
		req.Header.Add(remoteIPHeader, remoteIP1234.String())
		status, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status.StatusCode)
	}, options...)
}

func TestTrustedProxyPolicyForbidden(t *testing.T) {
	networks, err := httpserver.ParseNetworks("10.0.0.0/8")
	require.NoError(t, err)
	trustedProxyPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedProxyPolicy(trustedProxyPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, statusCode)
	}, options...)
}

func TestTrustedProxyPolicyOK(t *testing.T) {
	networks, err := httpserver.ParseNetworks("127.0.0.1/32", "::1/128")
	require.NoError(t, err)
	trustedProxyPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedProxyPolicy(trustedProxyPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, statusCode)
	}, options...)
}

func TestAllowedNetworksPolicyForbidden(t *testing.T) {
	networks, err := httpserver.ParseNetworks(remoteIP1234.String() + "/32")
	require.NoError(t, err)
	allowedNetworksPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithAllowedNetworksPolicy(allowedNetworksPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, statusCode)
	}, options...)
}

func TestAllowedNetworksPolicyOK(t *testing.T) {
	networks, err := httpserver.ParseNetworks("127.0.0.1/32", "::1/128")
	require.NoError(t, err)
	allowedNetworksPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithAllowedNetworksPolicy(allowedNetworksPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, statusCode)
	}, options...)
}

func TestCors(t *testing.T) {
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithCorsOptions(&cors.Options{}),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, statusCode)
	}, options...)
}

func runServerTest(t *testing.T, test func(*testing.T, *httpserver.Instance), options ...httpserver.ServerOption) {
	server, err := httpserver.Listen(t.Context(), "tcp", "localhost:0", options...)
	require.NoError(t, err)
	require.NotNil(t, server)
	server.HandleFunc("/", handlePing)
	server.HandleFunc("/remoteip", handleRemoteIP)
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

func handleRemoteIP(w http.ResponseWriter, r *http.Request) {
	remoteIP := httpserver.GetRequestRemoteIP(r)
	status := http.StatusOK
	if !remoteIP1234.Equal(remoteIP) {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
}

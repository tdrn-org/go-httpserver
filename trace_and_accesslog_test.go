//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

const remoteIPHeader string = "X-Remote-IP"

var remoteIP1234 net.IP = net.ParseIP("1.2.3.4")

func TestRemoteIPNoTrustedProxy(t *testing.T) {
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

func TestRemoteIPTrustedProxy(t *testing.T) {
	networks, err := httpserver.ParseNetworks(loNetworks...)
	require.NoError(t, err)
	trustedProxyPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedHeaders(remoteIPHeader),
		httpserver.WithTrustedProxyPolicy(trustedProxyPolicy),
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

func TestRemoteIPUntrustedProxy(t *testing.T) {
	networks, err := httpserver.ParseNetworks("10.0.0.0/8")
	require.NoError(t, err)
	trustedProxyPolicy := httpserver.AllowNetworks(networks)
	options := []httpserver.ServerOption{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithTrustedHeaders(remoteIPHeader),
		httpserver.WithTrustedProxyPolicy(trustedProxyPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		req, err := http.NewRequest(http.MethodGet, server.BaseURL().JoinPath("/remoteip").String(), nil)
		require.NoError(t, err)
		req.Header.Add(remoteIPHeader, remoteIP1234.String())
		status, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, status.StatusCode)
	}, options...)
}

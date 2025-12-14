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

var loNetworks []string = []string{"127.0.0.1/32", "::1/128"}

func TestParseNetworksSuccess(t *testing.T) {
	networks, err := httpserver.ParseNetworks(loNetworks...)
	require.NoError(t, err)
	require.Len(t, networks, 2)
}

func TestParseNetworksFailure(t *testing.T) {
	networks, err := httpserver.ParseNetworks("127.0.0.1")
	require.Error(t, err)
	require.Nil(t, networks)
}

func TestAllowedNetworksPolicyForbidden(t *testing.T) {
	networks, err := httpserver.ParseNetworks(remoteIP1234.String() + "/32")
	require.NoError(t, err)
	allowedNetworksPolicy := httpserver.AllowNetworks("", networks)
	options := []httpserver.OptionSetter{
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
	networks, err := httpserver.ParseNetworks(loNetworks...)
	require.NoError(t, err)
	allowedNetworksPolicy := httpserver.AllowNetworks("", networks)
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithAllowedNetworksPolicy(allowedNetworksPolicy),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		statusCode, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, statusCode)
	}, options...)
}

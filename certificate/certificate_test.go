//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate_test

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

func runProviderTest(t *testing.T, provider httpserver.CertificateProvider, httpClient *http.Client) {
	host, err := os.Hostname()
	require.NoError(t, err)
	serverAddr := net.JoinHostPort(host, strconv.Itoa(ACME_TLS_ALPN_01_CHALLENGE_PORT))
	server, err := httpserver.Listen(t.Context(), "tcp", serverAddr, httpserver.WithCertificateProvider(provider))
	require.NoError(t, err)
	server.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) { /* noop */ })
	go func() {
		err := server.Serve()
		if !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	}()
	response, err := httpClient.Get(server.BaseURL().String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	err = server.Shutdown(t.Context())
	require.NoError(t, err)
}

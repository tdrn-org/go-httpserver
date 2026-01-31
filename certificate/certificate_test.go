//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/go-httpserver/certificate"
	"github.com/tdrn-org/go-tlsconf"
)

func TestSimpleCertificateProvider(t *testing.T) {
	address := "localhost:0"
	cert, err := tlsconf.GenerateEphemeralCertificate(address, tlsconf.CertificateAlgorithmDefault, time.Hour)
	require.NoError(t, err)
	provider := &certificate.SimpleCertificateProvider{
		Certificates: []tls.Certificate{*cert},
	}
	trustedCerts := x509.NewCertPool()
	trustedCerts.AddCert(cert.Leaf)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustedCerts,
			},
		},
	}
	runProviderTest(t, address, provider, httpClient)
}

func runProviderTest(t *testing.T, address string, provider httpserver.CertificateProvider, httpClient *http.Client) {
	server, err := httpserver.Listen(t.Context(), "tcp", address, httpserver.WithCertificateProvider(provider))
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

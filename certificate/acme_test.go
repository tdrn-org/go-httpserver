//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver/certificate"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const ROOT_CERT_URL string = "https://localhost:15000/roots/0"
const INTERMEDIATE_CERT_URL string = "https://localhost:15000/intermediates/0"
const ACME_DIRECTORY_URL string = "https://localhost:14000/dir"
const ACME_TLS_ALPN_01_CHALLENGE_PORT int = 5001
const ACME_HTTP_01_CHALLENGE_PORT int = 5002

func TestACMECertificateProvider(t *testing.T) {
	host, err := os.Hostname()
	require.NoError(t, err)
	if !strings.Contains(strings.Trim(host, "."), ".") {
		t.Skip()
	}
	t.Run("http-01", testACMECertificateProviderHttp01)
	t.Run("tls-alpn-01", testACMECertificateProviderTlsAlpn01)
}

func testACMECertificateProviderHttp01(t *testing.T) {
	httpClient := pebbleClient(t)
	provider := &certificate.ACMECertificateProvider{
		AutoCertManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Client: &acme.Client{
				HTTPClient:   httpClient,
				DirectoryURL: ACME_DIRECTORY_URL,
			},
		},
		EnableHttp01Challenge: true,
		Http01ChallengePort:   ACME_HTTP_01_CHALLENGE_PORT,
	}
	host, err := os.Hostname()
	require.NoError(t, err)
	serverAddr := net.JoinHostPort(host, strconv.Itoa(ACME_TLS_ALPN_01_CHALLENGE_PORT))
	runProviderTest(t, serverAddr, provider, httpClient)
}

func testACMECertificateProviderTlsAlpn01(t *testing.T) {
	httpClient := pebbleClient(t)
	provider := &certificate.ACMECertificateProvider{
		AutoCertManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Client: &acme.Client{
				HTTPClient:   httpClient,
				DirectoryURL: ACME_DIRECTORY_URL,
			},
		},
	}
	host, err := os.Hostname()
	require.NoError(t, err)
	serverAddr := net.JoinHostPort(host, strconv.Itoa(ACME_TLS_ALPN_01_CHALLENGE_PORT))
	runProviderTest(t, serverAddr, provider, httpClient)
}

func pebbleClient(t *testing.T) *http.Client {
	trustedCerts := x509.NewCertPool()
	insecure := true
	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					for _, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)
						require.NoError(t, err)
						trustedCerts.AddCert(cert)
					}
					return nil
				},
			},
		},
	}
	trustedCertURLs := []string{ROOT_CERT_URL, INTERMEDIATE_CERT_URL}
	for _, url := range trustedCertURLs {
		response, err := insecureClient.Get(url)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		defer response.Body.Close()
		rest, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		block, rest := pem.Decode(rest)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE", block.Type)
		require.Len(t, rest, 0)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		trustedCerts.AddCert(cert)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustedCerts,
			},
		},
	}
}

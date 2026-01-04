//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver/certificate"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

func TestFileCertificateProvider(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	client1 := generateCertificateFiles(t, certFile, keyFile)
	provider := &certificate.FileCertificateProvider{
		CertFile:        certFile,
		KeyFile:         keyFile,
		RefreshInterval: 5 * time.Second,
	}
	runProviderTest(t, "localhost:0", provider, client1)
	client2 := generateCertificateFiles(t, certFile, keyFile)
	time.Sleep(10 * time.Second)
	runProviderTest(t, "localhost:0", provider, client2)
}

func generateCertificateFiles(t *testing.T, certFile, keyFile string) *http.Client {
	certificate, err := tlsserver.GenerateEphemeralCertificate("localhost", tlsserver.CertificateAlgorithmDefault)
	require.NoError(t, err)
	certBytes := &bytes.Buffer{}
	for _, certBlockBytes := range certificate.Certificate {
		err = pem.Encode(certBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBlockBytes})
		require.NoError(t, err)
	}
	keyBlockBytes, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBlockBytes})
	err = os.WriteFile(certFile, certBytes.Bytes(), os.FileMode(0600))
	require.NoError(t, err)
	err = os.WriteFile(keyFile, keyBytes, os.FileMode(0600))
	require.NoError(t, err)
	trustedCerts := x509.NewCertPool()
	trustedCerts.AddCert(certificate.Leaf)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustedCerts,
			},
		},
	}
}

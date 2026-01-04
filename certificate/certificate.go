//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate

import (
	"crypto/tls"
	"slices"

	"github.com/tdrn-org/go-httpserver"
)

// SimpleCertificateProvider is a certificate provider simply providing
// the statically given certificates.
type SimpleCertificateProvider struct {
	// Certificates is set to the certificates to be set in the
	// [tls.Config] returned by [httpserver.CertificateProvider.TLSConfig].
	Certificates []tls.Certificate
}

func (p *SimpleCertificateProvider) TLSConfig(_ *httpserver.Instance) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: slices.Clone(p.Certificates),
	}
	return tlsConfig, nil
}

func (p *SimpleCertificateProvider) Close() error {
	return nil
}

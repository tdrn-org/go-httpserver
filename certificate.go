//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"crypto/tls"
	"net"
)

// CertificateProvider interface is used to create the [tls.Config]
// for https processing.
type CertificateProvider interface {
	TLSConfig(server *Instance) (*tls.Config, error)
	Close() error
}

// WithCertificateProvider enables TLS using the given certificate provider.
func WithCertificateProvider(provider CertificateProvider) OptionSetterFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.certificateProvider = provider
	}
}

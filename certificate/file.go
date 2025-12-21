//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tdrn-org/go-httpserver"
)

const DefaultFileRefreshInterval time.Duration = 5 * time.Minute

// FileCertificateProvider implements a file based certificate provider loading
// the certificate from the given files using [tls.LoadX509KeyPair].
type FileCertificateProvider struct {
	// CertFile defines the certificate file to load. Certificate data must be PEM encoded.
	CertFile string
	// KeyFile defines the key file to load. Key data must be PEM encoded.
	KeyFile string
	// RefreshInterval defines the interval after which the files are reexamined
	// and are automatically reloaded in case of an update. The default value of 0
	// disables the reload.
	RefreshInterval   time.Duration
	nextStatTime      time.Time
	cachedModTime     time.Time
	cachedCertificate *tls.Certificate
}

func (p *FileCertificateProvider) TLSConfig(_ *httpserver.Instance) (*tls.Config, error) {
	err := p.reloadCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate (cause: %w)", err)
	}
	if p.RefreshInterval > 0 {
		refreshInterval := p.RefreshInterval
		go func() {
			time.Sleep(refreshInterval)
			err := p.reloadCertificate()
			if err != nil {
				slog.Error("certificate reload failed", slog.Any("err", err))
			}
		}()
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.cachedCertificate, nil
		},
	}
	return tlsConfig, nil
}

func (p *FileCertificateProvider) reloadCertificate() error {
	now := time.Now()
	if p.cachedCertificate != nil && !now.After(p.nextStatTime) {
		return nil
	}
	certFileInfo, err := os.Stat(p.CertFile)
	if err != nil {
		return err
	}
	keyFileInfo, err := os.Stat(p.KeyFile)
	if err != nil {
		return err
	}
	modTime := certFileInfo.ModTime()
	if keyFileInfo.ModTime().After(modTime) {
		modTime = keyFileInfo.ModTime()
	}
	if !modTime.After(p.cachedModTime) {
		return nil
	}
	cachedCertificate, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return err
	}
	if p.cachedCertificate != nil {
		slog.Info("certificate reloaded", slog.String("cert", p.CertFile), slog.String("key", p.KeyFile))
	} else {
		slog.Info("certificate loaded", slog.String("cert", p.CertFile), slog.String("key", p.KeyFile))
	}
	p.cachedCertificate = &cachedCertificate
	p.cachedModTime = modTime
	return nil
}

func (p *FileCertificateProvider) Close() error {
	return nil
}

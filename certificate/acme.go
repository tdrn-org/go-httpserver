//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package certificate

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/tdrn-org/go-httpserver"
	"golang.org/x/crypto/acme/autocert"
)

// ACMECertificateProvider implements an ACME based certificate provider
// creating certificates on-access via an ACME provider like LetsLet's Encrypt.
type ACMECertificateProvider struct {
	AutoCertManager       autocert.Manager
	EnableHttp01Challenge bool
	Http01ChallengePort   int
	http01ChallengeServer *http.Server
}

func (p *ACMECertificateProvider) TLSConfig(server *httpserver.Instance) (*tls.Config, error) {
	if p.EnableHttp01Challenge {
		err := p.startHttp01ChallengeServer(server)
		if err != nil {
			return nil, err
		}
	}
	tlsConfig := p.AutoCertManager.TLSConfig()
	return tlsConfig, nil
}

func (p *ACMECertificateProvider) startHttp01ChallengeServer(server *httpserver.Instance) error {
	serverListenerAddr := server.ListenerAddr()
	httpsAddr := serverListenerAddr.String()
	host, _, err := net.SplitHostPort(httpsAddr)
	if err != nil {
		return fmt.Errorf("unexpected https address '%s' (cause: %w)", httpsAddr, err)
	}
	port := p.Http01ChallengePort
	if port == 0 {
		port = 80
	}
	redirectTarget := server.BaseURL().String()
	p.http01ChallengeServer = &http.Server{
		Addr: net.JoinHostPort(host, strconv.Itoa(port)),
		Handler: p.AutoCertManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "HEAD" {
				http.Error(w, "Use HTTPS", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		})),
	}
	go func() {
		err := p.http01ChallengeServer.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Default().Error("failed to start http-01 challenge server", slog.Any("err", err))
		}
	}()
	return nil
}

func (p *ACMECertificateProvider) Close() error {
	if p.http01ChallengeServer != nil {
		return p.http01ChallengeServer.Close()
	}
	return nil
}

//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package httpserver provides functionality for easy setup of a secure
// http server based on the [net/http] implementation.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/rs/cors"
	"go.opentelemetry.io/otel/trace"
)

// Instance represents a single http server instance listening on a specifc address.
type Instance struct {
	defaultLogger         *slog.Logger
	address               string
	listener              net.Listener
	serveMux              *http.ServeMux
	certificateProvider   CertificateProvider
	tracerOptions         []trace.TracerOption
	accessLogger          *slog.Logger
	trustedHeaders        []string
	trustedProxyPolicy    AccessPolicy
	allowedNetworksPolicy AccessPolicy
	corsOptions           *cors.Options
	headers               []Header
	httpServer            http.Server
	logger                *slog.Logger
	closeFunc             func() error
}

// Listen creates a new http server instance listening on the given address.
//
// See [net.Listen] for parameter semantics.
func Listen(ctx context.Context, network string, address string, options ...OptionSetter) (*Instance, error) {
	server := &Instance{}
	listenConfig := &net.ListenConfig{}
	// Apply all options
	for _, option := range options {
		option.Apply(server, listenConfig)
	}
	// Set defaults where needed
	if server.defaultLogger == nil {
		server.defaultLogger = slog.Default()
	}
	if server.serveMux == nil {
		server.serveMux = http.NewServeMux()
	}
	if server.trustedHeaders == nil {
		server.trustedHeaders = defaultTrustedHeaders
	}
	// Setup handler chain according to options (last to first handler)
	server.httpServer.Handler = server.serveMux
	enableHeaders(server)
	enableCorsHandler(server)
	enableAllowedNetworkPolicy(server)
	enableTraceAndAccessLog(server)
	// Start to listen
	listener, err := listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on address '%s' (cause: %w)", address, err)
	}
	server.listener = listener
	listenerAddress := listener.Addr().String()
	host, _, _ := net.SplitHostPort(address)
	_, port, _ := net.SplitHostPort(listenerAddress)
	serverAddress := listenerAddress
	if host != "" && port != "" {
		serverAddress = host + ":" + port
	}
	server.address = serverAddress
	server.logger = server.defaultLogger.With(slog.String("address", listenerAddress))
	server.logger.Info("http server listening")
	server.closeFunc = server.listener.Close
	return server, nil
}

// MustListen invokes [Listen] and panics in case of any error.
func MustListen(ctx context.Context, network string, address string) *Instance {
	server, err := Listen(ctx, network, address)
	if err != nil {
		panic(err)
	}
	return server
}

// Addr gets this http server's named address.
//
// The returned address is based on the address parameter given during
// [Listen] call and any host name used during this call.
func (server *Instance) Addr() string {
	return server.address
}

// ListenerAddr gets this http server's listener address.
//
// Any host name given during [Listen] call are resolved to a concrete
// IP in the returned address.
func (server *Instance) ListenerAddr() net.Addr {
	return server.listener.Addr()
}

// BaseURL gets this http server's base URL.
func (server *Instance) BaseURL() *url.URL {
	scheme := "http"
	if server.certificateProvider != nil {
		scheme = "https"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   server.address,
	}
}

// Handle registers a handler for the given pattern.
//
// See [http.ServeMux.Handle] for details.
func (server *Instance) Handle(pattern string, handler http.Handler) {
	server.serveMux.Handle(pattern, handler)
}

// HandleFunc registers a handler function for the given pattern.
//
// See [http.ServeMux.HandleFunc] for details.
func (server *Instance) HandleFunc(pattern string, handler http.HandlerFunc) {
	server.serveMux.HandleFunc(pattern, handler)
}

// Serve invokes [http.Server.Serve] or [http.Server.ServeTLS] depending
// on the server configuration and starts accepting connections.
func (server *Instance) Serve() error {
	server.logger = server.logger.With(slog.String("baseURL", server.BaseURL().String()))
	server.closeFunc = server.httpServer.Close
	server.logger.Info("HTTP server starting")
	var serverErr error
	if server.certificateProvider != nil {
		tlsConfig, err := server.certificateProvider.TLSConfig(server)
		if err != nil {
			return err
		}
		defer server.certificateProvider.Close()
		server.httpServer.TLSConfig = tlsConfig
		serverErr = server.httpServer.ServeTLS(server.listener, "", "")
	} else {
		serverErr = server.httpServer.Serve(server.listener)
	}
	if errors.Is(serverErr, http.ErrServerClosed) {
		server.logger.Info("HTTP server stopped")
	}
	return serverErr
}

// Ping pings the http server by accessing the base URL.
//
// An error indicates, the connection could not be established.
// Otherwise the returned http status code is returned.
func (server *Instance) Ping() (int, error) {
	server.logger.Debug("pinging HTTP server")
	rsp, err := http.Get(server.BaseURL().String())
	if err == nil {
		server.logger.Debug("ping succeeded", slog.String("status", rsp.Status))
		return rsp.StatusCode, nil
	}
	defer rsp.Body.Close()
	return -1, err
}

// Shutdown invokes [http.Server,Shutdown] and shuts down the http server.
func (server *Instance) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

// Close invokes [http.Server.Close] or [net.Listener.Close] depending on
// the http server's state.
func (server *Instance) Close() error {
	return server.closeFunc()
}

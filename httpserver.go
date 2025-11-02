//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package httpserver provides functionality for easy setup of a secure
// http server using either [net/http] standard implementation or a
// compatible one.
package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
)

// Instance represents a single http server instance listening on a specifc address.
type Instance struct {
	address  string
	listener net.Listener
	logger   *slog.Logger
}

// Listen creates a new http server instance listening on the given address.
//
// See [net.Listen] for parameter semantics.
func Listen(ctx context.Context, network string, address string) (*Instance, error) {
	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on address '%s' (cause: %w)", address, err)
	}
	listenerAddress := listener.Addr().String()
	host, _, _ := net.SplitHostPort(address)
	_, port, _ := net.SplitHostPort(listenerAddress)
	instanceAddress := listenerAddress
	if host != "" && port != "" {
		instanceAddress = host + ":" + port
	}
	logger := slog.Default().With(slog.String("address", instanceAddress))
	logger.Info("http server listening")
	instance := &Instance{
		address:  instanceAddress,
		listener: listener,
		logger:   logger,
	}
	return instance, nil
}

// MustListen invokes [Listen] and panics in case of any error.
func MustListen(ctx context.Context, network string, address string) *Instance {
	i, err := Listen(ctx, network, address)
	if err != nil {
		panic(err)
	}
	return i
}

// Close closes this http server's listener.
func (i *Instance) Close() error {
	return i.listener.Close()
}

// Addr gets this http server's named address.
//
// The returned address is based on the address parameter given during
// [Listen] call and any host name used during this call.
func (i *Instance) Addr() string {
	return i.address
}

// ListenerAddr gets this http server's listener address.
//
// Any host name given during [Listen] call are resolved to a concrete
// IP in the returned address.
func (i *Instance) ListenerAddr() net.Addr {
	return i.listener.Addr()
}

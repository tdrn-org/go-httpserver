//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"fmt"
	"net"
	"net/http"
)

type AccessPolicy interface {
	Allow(remoteIP net.IP) bool
}

func WithTrustedProxyPolicy(policy AccessPolicy) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.trustedProxyPolicy = policy
	}
}

func enableTrustedProxyPolicy(server *Instance) {
	if server.trustedProxyPolicy != nil {
		server.httpServer.Handler = &accessPolicyHandler{
			handler: server.httpServer.Handler,
			policy:  server.trustedProxyPolicy,
		}
	}
}

type accessPolicyHandler struct {
	handler http.Handler
	policy  AccessPolicy
}

func (h *accessPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := GetRequestRemoteIP(r)
	if !h.policy.Allow(remoteIP) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func ParseNetworks(cidrs ...string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse network: '%s' (cause: %w)", cidr, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func AllowNetworks(networks []*net.IPNet) AccessPolicy {
	if len(networks) == 0 {
		return nil
	}
	return &networkAccessPolicy{networks: networks}
}

type networkAccessPolicy struct {
	networks []*net.IPNet
}

func (p *networkAccessPolicy) Allow(remoteIP net.IP) bool {
	for _, network := range p.networks {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

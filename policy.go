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

// AccessPolicy interface is used to define access restrictions
// based on the accessing remote IP.
type AccessPolicy interface {
	// Allow checks whether the given remote IP should be granted access.
	Allow(remoteIP net.IP) bool
}

// WithAllowedNetworksPolicy restricts http server access to the given access policy.
func WithAllowedNetworksPolicy(policy AccessPolicy) ServerOptionFunc {
	return func(server *Instance, _ *net.ListenConfig) {
		server.allowedNetworksPolicy = policy
	}
}

func enableAllowedNetworkPolicy(server *Instance) {
	if server.allowedNetworksPolicy != nil {
		server.httpServer.Handler = &accessPolicyHandler{
			handler: server.httpServer.Handler,
			policy:  server.allowedNetworksPolicy,
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

// ParseNetworks parses the given CIDR network definitions using
// [net.ParseCIDR] and returns the parsed networks.
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

// AllowNetworks creates an access policy restricting access
// to the given networks.
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

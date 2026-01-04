//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// AccessPolicy interface is used to define access restrictions
// based on the accessing remote IP.
type AccessPolicy interface {
	// Name gets the name of this policy.
	Name() string
	// Allow checks whether the given remote IP should be granted access.
	Allow(remoteIP net.IP) bool
}

// WithAllowedNetworksPolicy restricts http server access to the given access policy.
func WithAllowedNetworksPolicy(policy AccessPolicy) OptionSetterFunc {
	return func(server *Instance, _ *net.ListenConfig) {
		server.allowedNetworksPolicy = policy
	}
}

func enableAllowedNetworkPolicy(server *Instance) {
	if server.allowedNetworksPolicy != nil {
		server.httpServer.Handler = &accessPolicyHandler{
			handler: server.httpServer.Handler,
			policy:  server.allowedNetworksPolicy,
			logger:  func() *slog.Logger { return server.logger },
		}
	}
}

type accessPolicyHandler struct {
	handler http.Handler
	policy  AccessPolicy
	logger  func() *slog.Logger
}

func (h *accessPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := RequestRemoteIP(r)
	if !h.policy.Allow(remoteIP) {
		h.logger().Debug("http server access denied by policy", slog.Any("remoteIP", remoteIP), slog.String("policy", h.policy.Name()))
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
func AllowNetworks(name string, networks []*net.IPNet) AccessPolicy {
	if len(networks) == 0 {
		return nil
	}
	policyName := name
	if policyName == "" {
		policyName = fmt.Sprintf("allow: %v", networks)
	}
	return &networkAccessPolicy{name: policyName, networks: networks}
}

type networkAccessPolicy struct {
	name     string
	networks []*net.IPNet
}

func (p *networkAccessPolicy) Name() string {
	return p.name
}

func (p *networkAccessPolicy) Allow(remoteIP net.IP) bool {
	for _, network := range p.networks {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

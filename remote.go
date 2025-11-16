//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"net"
	"net/http"
	"strings"
)

// GetRemoteIP determines the remote IP sending the given http request.
//
// The given trusted headers are evaluated to determine the remote IP in case
// of a proxy setup. If no headers are given or they are empty, the remote IP
// associated with the given http request is returned.
func GetRemoteIP(r *http.Request, trustedHeaders ...string) string {
	for _, trustedHeader := range trustedHeaders {
		remoteIP := r.Header.Get(trustedHeader)
		if remoteIP != "" {
			i := strings.Index(remoteIP, ",")
			if i >= 0 {
				remoteIP = remoteIP[:i]
			}
			if remoteIP != "" {
				return remoteIP
			}
		}
	}
	remoteAddr := r.RemoteAddr
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}
	return remoteIP
}

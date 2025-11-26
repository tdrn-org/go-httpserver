//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"net"

	"github.com/rs/cors"
)

// WithCorsOptions enables CORS using the given [cors.Options].
func WithCorsOptions(options *cors.Options) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.corsOptions = options
	}
}

func enableCorsHandler(server *Instance) {
	if server.corsOptions != nil {
		server.httpServer.Handler = cors.New(*server.corsOptions).Handler(server.httpServer.Handler)
	}
}

//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"net"
)

// OptionSetter instances are used to apply different options
// to the http server during creation.
//
// See the various With* functions for concrete options.
type OptionSetter interface {
	Apply(server *Instance, listenConfig *net.ListenConfig)
}

// OptionSetterFunc functions are used to apply different options
// to the http server during creation.
//
// See the various With* functions for concrete options.
type OptionSetterFunc func(server *Instance, listenConfig *net.ListenConfig)

func (f OptionSetterFunc) Apply(server *Instance, listenConfig *net.ListenConfig) {
	f(server, listenConfig)
}

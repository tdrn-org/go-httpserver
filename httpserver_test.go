//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

func TestListenTCP(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "tcp", "localhost:0")
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

func TestListenUnix(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "TestListenUnix.sock"))
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

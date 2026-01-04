//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
)

//go:embed all:testdata/*
var testdata embed.FS

func testdataFS() (fs.ReadDirFS, error) {
	sub, err := fs.Sub(testdata, "testdata")
	if err != nil {
		return nil, err
	}
	return sub.(fs.ReadDirFS), nil
}

func TestListenTCPLocalhost(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "tcp", "localhost:0")
	require.NoError(t, err)
	require.NotNil(t, server)
	err = server.Close()
	require.NoError(t, err)
}

func TestListenTCPAny(t *testing.T) {
	server, err := httpserver.Listen(t.Context(), "tcp", ":0")
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

func TestMustListen(t *testing.T) {
	require.Panics(t, func() {
		httpserver.MustListen(t.Context(), "tcp", "localhost:-1")
	})
}

func TestPing(t *testing.T) {
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := server.Ping()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}, options...)
}

const testNetwork string = "tcp"
const testAddress string = "localhost:0"

const rootPath string = "/"
const remoteIPPath string = "/remoteip"
const headerPath string = "/header"
const testHtmlPath string = "/test.html"

func runServerTest(t *testing.T, test func(*testing.T, *httpserver.Instance), options ...httpserver.OptionSetter) {
	server, err := httpserver.Listen(t.Context(), testNetwork, testAddress, options...)
	require.NoError(t, err)
	require.NotNil(t, server)
	server.HandleFunc(rootPath, handleNoop)
	server.HandleFunc(remoteIPPath, handleRemoteIP)
	server.HandleFunc(headerPath, handleNoop)
	server.HandleFunc(testHtmlPath, handleTestHtml)
	go func() {
		err := server.Serve()
		if !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	}()
	test(t, server)
	err = server.Shutdown(t.Context())
	require.NoError(t, err)
	err = server.Close()
	require.NoError(t, err)
}

func handleNoop(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func handleRemoteIP(w http.ResponseWriter, r *http.Request) {
	remoteIP := httpserver.RequestRemoteIP(r)
	status := http.StatusOK
	if !remoteIP1234.Equal(remoteIP) {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
}

func handleTestHtml(w http.ResponseWriter, _ *http.Request) {
	fs, err := testdataFS()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	file, err := fs.Open("test.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = io.Copy(w, file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

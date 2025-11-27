//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/go-httpserver/csp"
)

const contentSecurityPolicyValue string = "base-uri 'self';form-action 'self';frame-ancestors 'self';default-src 'self';connect-src 'self';script-src 'self' 'sha256-GyzGmXG7QmPBGeqPxQFC/UlXYp6LNGi+5iiYCRDzREw=';style-src 'self' 'sha256-tcbDxjMo+xKqM21aCGYbs/QAJqB7yUXC06oPWDapBgc=';img-src 'self';"

func TestContentSecurityPolicy(t *testing.T) {
	contentSecurityPolicy := &csp.ContentSecurityPolicy{
		BaseUri:       []string{csp.PolicySelf},
		FormAction:    []string{csp.PolicySelf},
		FrameAncestor: []string{csp.PolicySelf},
		DefaultSrc:    []string{csp.PolicySelf},
		ConnectSrc:    []string{csp.PolicySelf},
		ScriptSrc:     []string{csp.PolicySelf},
		StyleSrc:      []string{csp.PolicySelf},
		ImgSrc:        []string{csp.PolicySelf},
	}
	contentSecurityPolicy.AddHashes(csp.HashAlgSHA256, testdataFS())
	options := []httpserver.OptionSetter{
		httpserver.WithDefaultAccessLog(),
		httpserver.WithHeaders(contentSecurityPolicy.Header()),
	}
	runServerTest(t, func(t *testing.T, server *httpserver.Instance) {
		status, err := http.Get(server.BaseURL().JoinPath("/test.html").String())
		require.NoError(t, err)
		defer status.Body.Close()
		require.Equal(t, contentSecurityPolicyValue, status.Header.Get(csp.HeaderKey))
		require.Equal(t, http.StatusOK, status.StatusCode)
	}, options...)
}

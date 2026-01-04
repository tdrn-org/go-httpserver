//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package csp_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-httpserver/csp"
)

func TestCSPHashes(t *testing.T) {
	for _, alg := range []csp.HashAlg{csp.HashAlgSHA256, csp.HashAlgSHA384, csp.HashAlgSHA512} {
		t.Run(alg.Name(), func(t *testing.T) {
			hashPrefix := "'" + alg.Name() + "-"
			hash := alg.GenerateHash("display: contents")
			require.True(t, strings.HasPrefix(hash, hashPrefix))
			require.True(t, len(hash) > len(hashPrefix))
		})
	}
}

//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package csp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/tdrn-org/go-httpserver"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// HashAlg represents the supported algorithms for CSP hash generation.
type HashAlg string

const (
	// SHA256 hash algorithm
	HashAlgSHA256 HashAlg = "sha256"
	// SHA384 hash algorithm
	HashAlgSHA384 HashAlg = "sha384"
	// SHA512 hash algorithm
	HashAlgSHA512 HashAlg = "sha512"
)

// Name gets the name of this hash algorithm.
func (alg HashAlg) Name() string {
	return string(alg)
}

// New creates a new instance of this hash algorithm.
func (alg HashAlg) New() hash.Hash {
	switch alg {
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	}
	panic("unrecognized CSP hash algorithm: " + alg)
}

// GenerateHash generates the hash directive for the given data.
//
// The returned directive already contains the prefix identifying this hash algorithm
// and is ready for use within a CSP header.
func (alg HashAlg) GenerateHash(data string) string {
	hash := alg.New()
	hash.Write([]byte(data))
	return "'" + alg.Name() + "-" + base64.StdEncoding.EncodeToString(hash.Sum(nil)) + "'"
}

// Content-Security-Policy header key
const HeaderKey string = "Content-Security-Policy"

// Default defines the restrictive default CSP policy used
// in case no explicit CSP policy can be determined for a requested path.
const Default string = "base-uri: 'none';default-src: 'none';"

// CSP source 'none'
const SrcNone string = "'none'"

// CSP source 'self'
const SrcSelf string = "'self'"

// CSP source 'unsafe-inline'
const SrcUnsafeInline string = "'unsafe-inline'"

// CSP source 'unsafe-eval'
const SrcUnsafeEval string = "'unsafe-eval'"

// CSP source https:
const SrcHttps string = "https:"

// CSP source data:
const SrcData string = "data:"

// ContentSecurityPolicy represents a template for CSP header creation.
//
// The CSP header is build by collecting the defined directives. Empty directives
// are ignored.
type ContentSecurityPolicy struct {
	// base-uri directive content.
	BaseUri []string
	// form-action directive content.
	FormAction []string
	// frame-ancestor directive content.
	FrameAncestor []string
	// default-src directive content.
	DefaultSrc []string
	// connect-src directive content.
	ConnectSrc []string
	// script-src directive content.
	ScriptSrc []string
	// style-src directive content.
	StyleSrc []string
	// img-src directive content.
	ImgSrc       []string
	scriptHashes map[string][]string
	styleHashes  map[string][]string
}

// AddHashes generates script and style hashes for inline scripts and styles
// found within html files contained in the given [fs.ReadDirFS] using the
// given hash algorithm.
func (p *ContentSecurityPolicy) AddHashes(alg HashAlg, fs fs.ReadDirFS) error {
	return p.addHashes(alg, fs, ".")
}

func (p *ContentSecurityPolicy) addHashes(alg HashAlg, fs fs.ReadDirFS, dir string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s' (cause: %w)", dir, err)
	}
	for _, entry := range entries {
		entryType := entry.Type()
		entryName := entry.Name()
		entryPath := filepath.Join(dir, entryName)
		if entryType.IsRegular() {
			err = p.addFileHashes(alg, fs, entryPath)
		} else if entryType.IsDir() {
			err = p.addHashes(alg, fs, entryPath)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *ContentSecurityPolicy) addFileHashes(alg HashAlg, fs fs.ReadDirFS, path string) error {
	if !strings.HasSuffix(path, ".html") {
		return nil
	}
	file, err := fs.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' (cause: %w)", path, err)
	}
	defer file.Close()
	node, err := html.Parse(file)
	if err != nil {
		return fmt.Errorf("failed to parse file '%s' (cause: %w)", path, err)
	}
	p.addNodeHashes(alg, path, node)
	return nil
}

func (p *ContentSecurityPolicy) addNodeHashes(alg HashAlg, path string, node *html.Node) {
	if node.DataAtom == atom.Script {
		hash := alg.GenerateHash(node.FirstChild.Data)
		if p.scriptHashes == nil {
			p.scriptHashes = make(map[string][]string)
		}
		slog.Default().Debug("script hash generated", slog.String("path", path), slog.String("alg", alg.Name()))
		p.scriptHashes[path] = append(p.scriptHashes[path], hash)
	}
	for _, attr := range node.Attr {
		if attr.Key == "style" {
			hash := alg.GenerateHash(attr.Val)
			if p.styleHashes == nil {
				p.styleHashes = make(map[string][]string)
			}
			slog.Default().Debug("style hash generated", slog.String("path", path), slog.String("alg", alg.Name()))
			p.styleHashes[path] = append(p.styleHashes[path], hash)
		}
	}
	for child := range node.ChildNodes() {
		p.addNodeHashes(alg, path, child)
	}
}

// Header creates a [httpserver.Header] instance representing the this CSP template.
func (p *ContentSecurityPolicy) Header() httpserver.Header {
	policyCount := len(p.scriptHashes)
	if policyCount < len(p.styleHashes) {
		policyCount = len(p.styleHashes)
	}
	policies := make(map[string]string, policyCount)
	for path := range p.scriptHashes {
		policies[path] = p.policy(path)
	}
	for path := range p.styleHashes {
		policy := policies[path]
		if policy == "" {
			policies[path] = p.policy(path)
		}
	}
	return &contentSecurityPolicyHeader{policies: policies, defaultPolicy: Default}
}

func (p *ContentSecurityPolicy) policy(path string) string {
	buffer := &contentSecurityPolicyBuilder{}
	if len(p.BaseUri) > 0 {
		buffer.writeSimpleDirective("base-uri", p.BaseUri)
	}
	if len(p.FormAction) > 0 {
		buffer.writeSimpleDirective("form-action", p.FormAction)
	}
	if len(p.FrameAncestor) > 0 {
		buffer.writeSimpleDirective("frame-ancestors", p.FrameAncestor)
	}
	if len(p.DefaultSrc) > 0 {
		buffer.writeFetchDirective("default-src", p.DefaultSrc, nil)
	}
	if len(p.ConnectSrc) > 0 {
		buffer.writeFetchDirective("connect-src", p.ConnectSrc, nil)
	}
	pathScriptHashes := p.scriptHashes[path]
	if len(p.ScriptSrc) > 0 || len(pathScriptHashes) > 0 {
		buffer.writeFetchDirective("script-src", p.ScriptSrc, pathScriptHashes)
	}
	pathStyleHashes := p.styleHashes[path]
	if len(p.StyleSrc) > 0 || len(pathStyleHashes) > 0 {
		buffer.writeFetchDirective("style-src", p.StyleSrc, pathStyleHashes)
	}
	if len(p.ImgSrc) > 0 {
		buffer.writeFetchDirective("img-src", p.ImgSrc, nil)
	}
	return buffer.String()
}

type contentSecurityPolicyHeader struct {
	policies      map[string]string
	defaultPolicy string
}

func (h *contentSecurityPolicyHeader) Apply(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || strings.HasSuffix(path, "/") {
		path = path + "index.html"
	}
	policy := h.policies[path]
	if policy == "" {
		policy = h.defaultPolicy
	}
	w.Header().Add(HeaderKey, policy)
}

type contentSecurityPolicyBuilder struct {
	strings.Builder
}

func (b *contentSecurityPolicyBuilder) writeSimpleDirective(directive string, srcs []string) {
	b.WriteString(directive)
	for _, src := range srcs {
		b.WriteRune(' ')
		b.WriteString(src)
	}
	b.WriteRune(';')
}

func (b *contentSecurityPolicyBuilder) writeFetchDirective(directive string, srcs []string, hashes []string) {
	b.WriteString(directive)
	ignoreHashes := false
	for _, src := range srcs {
		ignoreHashes = ignoreHashes || (src == SrcUnsafeInline)
		b.WriteRune(' ')
		b.WriteString(src)
	}
	if !ignoreHashes {
		for _, hash := range hashes {
			b.WriteRune(' ')
			b.WriteString(hash)
		}
	}
	b.WriteRune(';')
}

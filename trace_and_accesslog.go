//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	tracehelper "github.com/tdrn-org/go-trace"

	"go.opentelemetry.io/otel/trace"
)

// Standard header for forwarding the remote IP.
const Header_X_Forwarded_For string = "X-Forwarded-For"

var defaultTrustedHeaders []string = []string{
	Header_X_Forwarded_For,
}

type contextKey string

const remoteIPContextKey contextKey = "remoteIP"

// RemoteIP gets the remote IP for the given [context.Context].
// nil is returned in case the remote IP could not be determined.
func RemoteIP(ctx context.Context) (netip.Addr, bool) {
	value := ctx.Value(remoteIPContextKey)
	if value == nil {
		return netip.Addr{}, false
	}
	return value.(netip.Addr), true
}

// RequestRemoteIP gets the remote IP for the given [http.Request].
// nil is returned in case the remote IP could not be determined.
func RequestRemoteIP(r *http.Request) (netip.Addr, bool) {
	value := r.Context().Value(remoteIPContextKey)
	if value == nil {
		return requestRemoteIP(r)
	}
	return value.(netip.Addr), true
}

// WithTracerOptions sets the [trace.TracerOptions] to use for for setting up
// the [otel.Tracer] instance used for tracing.
func WithTracerOptions(opts ...trace.TracerOption) OptionSetterFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.tracerOptions = opts
	}
}

// WithDefaultAccessLog enables the access log using the default
// logger returned by [slog.Default].
func WithDefaultAccessLog() OptionSetterFunc {
	return WithAccessLog(slog.Default())
}

// WithAccessLog enables the access log using given logger.
func WithAccessLog(logger *slog.Logger) OptionSetterFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.accessLogger = logger
	}
}

// WithTrustedHeaders sets the request headers to examine to
// determine the remote IP.
func WithTrustedHeaders(headers ...string) OptionSetterFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.trustedHeaders = headers
	}
}

// WithTrustedProxyPolicy sets the access policy used to determine
// whether the accessing host is a trusted proxy and it's headers
// can be savely evaluated.
func WithTrustedProxyPolicy(policy AccessPolicy) OptionSetterFunc {
	return func(server *Instance, _ *net.ListenConfig) {
		server.trustedProxyPolicy = policy
	}
}

func enableTraceAndAccessLog(server *Instance) {
	server.httpServer.Handler = &traceAndAccessLogHandler{
		handler:            server.httpServer.Handler,
		tracer:             tracehelper.NewTracePoint[Instance]("ServeHTTP", server.tracerOptions...),
		logger:             server.accessLogger,
		trustedHeaders:     server.trustedHeaders,
		trustedProxyPolicy: server.trustedProxyPolicy,
	}
}

type traceAndAccessLogHandler struct {
	handler            http.Handler
	tracer             *tracehelper.TracePoint
	logger             *slog.Logger
	trustedHeaders     []string
	trustedProxyPolicy AccessPolicy
}

func (h *traceAndAccessLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceR, span := h.tracer.StartHttpServer(r)
	defer span.End()
	wrappedW := tracehelper.TraceHttpResponse(span, w)
	defer wrappedW.Release()

	remoteIP, ok := requestRemoteIP(r)
	if ok && (h.trustedProxyPolicy == nil || h.trustedProxyPolicy.Allow(remoteIP)) {
		remoteIP, ok = requestRemoteIP(r, h.trustedHeaders...)
	}
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	remoteCtx := context.WithValue(traceR.Context(), remoteIPContextKey, remoteIP)
	remoteR := r.WithContext(remoteCtx)
	if h.logger != nil {
		log := &logBuilder{}
		log.appendHost(remoteIP.String())
		log.appendTime()
		log.appendRequest(r.Method, r.URL.Path, r.Proto)
		h.handler.ServeHTTP(wrappedW, remoteR)
		log.appendStatus(wrappedW.StatusCode(), wrappedW.Written())
		h.logger.Info(log.String())
	} else {
		h.handler.ServeHTTP(wrappedW, remoteR)
	}
}

func requestRemoteIP(r *http.Request, trustedHeaders ...string) (netip.Addr, bool) {
	for _, trustedHeader := range trustedHeaders {
		trustedHeaderValue := r.Header.Get(trustedHeader)
		remoteIPStrings := strings.Split(trustedHeaderValue, ",")
		for _, remoteIPString := range remoteIPStrings {
			remoteIP, err := netip.ParseAddr(remoteIPString)
			if err == nil {
				return remoteIP, true
			}
		}
	}
	remoteAddr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return remoteAddr.Addr(), true
}

type logBuilder struct {
	strings.Builder
}

func (b *logBuilder) appendHost(remoteIP string) {
	if remoteIP != "" {
		b.WriteString(remoteIP)
	} else {
		b.WriteRune('-')
	}
	b.WriteString(" - -")
}

func (b *logBuilder) appendTime() {
	b.WriteString(time.Now().Format(" [02/Jan/2006:15:04:05 -0700]"))
}

func (b *logBuilder) appendRequest(method, path, proto string) {
	b.WriteString(" \"")
	b.WriteString(method)
	b.WriteRune(' ')
	b.WriteString(path)
	b.WriteRune(' ')
	b.WriteString(proto)
	b.WriteRune('"')
}

func (b *logBuilder) appendStatus(statusCode, written int) {
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(statusCode))
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(written))
}

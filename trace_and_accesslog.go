//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Standard header for forwarding the remote IP.
const Header_X_Forwarded_For string = "X-Forwarded-For"

var defaultTrustedHeaders []string = []string{
	Header_X_Forwarded_For,
}

type contextKey string

const remoteIPContextKey contextKey = "remoteIP"

// GetRequestRemoteIP gets the remote IP the given [http.Request] is
// originating from.
func GetRequestRemoteIP(r *http.Request) net.IP {
	return r.Context().Value(remoteIPContextKey).(net.IP)
}

// WithTracerOptions sets the [trace.TracerOptions] to use for for setting up
// the [otel.Tracer] instance used for tracing.
func WithTracerOptions(opts ...trace.TracerOption) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.tracerOptions = opts
	}
}

// WithDefaultAccessLog enables the access log using the default
// logger returned by [slog.Default].
func WithDefaultAccessLog() ServerOptionFunc {
	return WithAccessLog(slog.Default())
}

// WithAccessLog enables the access log using given logger.
func WithAccessLog(logger *slog.Logger) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.accessLogger = logger
	}
}

// WithTrustedHeaders sets the request headers to examine to
// determine the remote IP.
func WithTrustedHeaders(headers ...string) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.trustedHeaders = headers
	}
}

// WithTrustedProxyPolicy sets the access policy used to determine
// whether the accessing host is a trusted proxy and it's headers
// can be savely evaluated.
func WithTrustedProxyPolicy(policy AccessPolicy) ServerOptionFunc {
	return func(server *Instance, _ *net.ListenConfig) {
		server.trustedProxyPolicy = policy
	}
}

func enableTraceAndAccessLog(server *Instance) {
	server.httpServer.Handler = &traceAndAccessLogHandler{
		handler:            server.httpServer.Handler,
		tracer:             otel.Tracer(reflect.TypeFor[Instance]().PkgPath(), server.tracerOptions...),
		logger:             server.accessLogger,
		trustedHeaders:     server.trustedHeaders,
		trustedProxyPolicy: server.trustedProxyPolicy,
	}
}

type traceAndAccessLogHandler struct {
	handler            http.Handler
	tracer             trace.Tracer
	logger             *slog.Logger
	trustedHeaders     []string
	trustedProxyPolicy AccessPolicy
}

const httpStatusCodeAttributeKey string = "http.status_code"

func (h *traceAndAccessLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ServeHTTP", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("path", r.URL.Path)))
	defer span.End()
	remoteIP := getRemoteIP(r)
	if h.trustedProxyPolicy == nil || h.trustedProxyPolicy.Allow(remoteIP) {
		remoteIP = getRemoteIP(r, h.trustedHeaders...)
	}
	if remoteIP == nil {
		w.WriteHeader(http.StatusBadRequest)
		span.SetAttributes(attribute.Int(httpStatusCodeAttributeKey, http.StatusBadRequest))
		return
	}
	remoteCtx := context.WithValue(traceCtx, remoteIPContextKey, remoteIP)
	remoteR := r.WithContext(remoteCtx)
	wrappedW := &wrappedResponseWriter{wrapped: w, statusCode: http.StatusOK}
	if h.logger != nil {
		log := &logBuilder{}
		log.appendHost(remoteIP.String())
		log.appendTime()
		log.appendRequest(r.Method, r.URL.Path, r.Proto)
		h.handler.ServeHTTP(wrappedW, remoteR)
		log.appendStatus(wrappedW.statusCode, wrappedW.written)
		h.logger.Info(log.String())
	} else {
		h.handler.ServeHTTP(wrappedW, remoteR)
	}
	span.SetAttributes(attribute.Int(httpStatusCodeAttributeKey, wrappedW.statusCode))
}

func getRemoteIP(r *http.Request, trustedHeaders ...string) net.IP {
	for _, trustedHeader := range trustedHeaders {
		trustedHeaderValue := r.Header.Get(trustedHeader)
		remoteIPStrings := strings.Split(trustedHeaderValue, ",")
		for _, remoteIPString := range remoteIPStrings {
			remoteIP := net.ParseIP(remoteIPString)
			if remoteIP != nil {
				return remoteIP
			}
		}
	}
	remoteAddr := r.RemoteAddr
	remoteIPString, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIPString = remoteAddr
	}
	return net.ParseIP(remoteIPString)
}

type wrappedResponseWriter struct {
	wrapped    http.ResponseWriter
	written    int
	statusCode int
}

func (w *wrappedResponseWriter) Header() http.Header {
	return w.wrapped.Header()
}

func (w *wrappedResponseWriter) Write(b []byte) (int, error) {
	written, err := w.wrapped.Write(b)
	if written > 0 {
		w.written += written
	}
	return written, err
}

func (w *wrappedResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.wrapped.WriteHeader(statusCode)
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

func (b *logBuilder) appendRequest(method string, path string, proto string) {
	b.WriteString(" \"")
	b.WriteString(method)
	b.WriteRune(' ')
	b.WriteString(path)
	b.WriteRune(' ')
	b.WriteString(proto)
	b.WriteRune('"')
}

func (b *logBuilder) appendStatus(statusCode int, written int) {
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(statusCode))
	b.WriteRune(' ')
	b.WriteString(strconv.Itoa(written))
}

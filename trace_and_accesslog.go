//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
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

func WithTracerOptions(opts ...trace.TracerOption) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.tracerOptions = opts
	}
}

func WithAccessLog(logger *slog.Logger) ServerOptionFunc {
	return func(server *Instance, listenConfig *net.ListenConfig) {
		server.accessLogger = logger
	}
}

func enableTraceAndAccessLog(server *Instance) {
	server.httpServer.Handler = &traceAndAccessLogHandler{
		handler: server.httpServer.Handler,
		tracer:  otel.Tracer(reflect.TypeFor[Instance]().PkgPath(), server.tracerOptions...),
		logger:  server.accessLogger,
	}
}

type traceAndAccessLogHandler struct {
	handler http.Handler
	tracer  trace.Tracer
	logger  *slog.Logger
}

func (h *traceAndAccessLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ServeHTTP", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("path", r.URL.Path)))
	defer span.End()

	// TODO: handle proxy and geoip case
	remoteIP := GetRemoteIP(r)
	traceR := r.WithContext(traceCtx)
	wrappedW := &wrappedResponseWriter{wrapped: w, statusCode: http.StatusOK}
	if h.logger != nil {
		log := &logBuilder{}
		log.appendHost(remoteIP)
		log.appendTime()
		log.appendRequest(r.Method, r.URL.Path, r.Proto)
		h.handler.ServeHTTP(wrappedW, traceR)
		log.appendStatus(wrappedW.statusCode, wrappedW.written)
		h.logger.Info(log.String())
	} else {
		h.handler.ServeHTTP(wrappedW, traceR)
	}
	span.SetAttributes(attribute.Int("http.status_code", wrappedW.statusCode))
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

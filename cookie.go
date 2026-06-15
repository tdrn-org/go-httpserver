//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package httpserver

import (
	"net/http"
)

type CookieHandler struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
	MaxAge   int
}

func (h *CookieHandler) Set(w http.ResponseWriter, value string, remember bool) error {
	maxAge := 0
	if remember {
		maxAge = h.MaxAge
	}
	return h.set(w, value, maxAge)
}

func (h *CookieHandler) Get(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(h.Name)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

func (h *CookieHandler) Delete(w http.ResponseWriter) {
	h.set(w, "", -1)
}

func (h *CookieHandler) set(w http.ResponseWriter, value string, maxAge int) error {
	cookie := &http.Cookie{
		Name:     h.Name,
		Value:    value,
		Domain:   h.Domain,
		Path:     h.Path,
		MaxAge:   maxAge,
		Secure:   h.Secure,
		HttpOnly: true,
		SameSite: h.SameSite,
	}
	http.SetCookie(w, cookie)
	return nil
}

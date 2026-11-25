package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

// newRouter returns the HTTP mux. The beacon endpoint and the lure credential
// sink are registered on their own exact paths; everything else 404s so the
// listener gives nothing away by probing.
func newRouter(h *c2Handler, path string, a *credsHandler, authPath string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(path, h)
	mux.Handle(authPath, a)
	return mux
}

// newServer builds the HTTPS server with hardened protocol defaults.
func newServer(h http.Handler, cert tls.Certificate) *http.Server {
	return &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

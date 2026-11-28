package cloudserver

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Same-origin guard for the dashboard backup mutation routes. Dashboard
// sessions are SameSite=Lax cookies, which a cross-site form POST does not
// carry; this check additionally refuses a same-site but cross-origin POST
// (for example from a sibling subdomain), which Lax cookies do not stop.
//
// A request is refused when Sec-Fetch-Site is present and is not
// "same-origin", or when Origin is present and its scheme and host differ from
// the request's effective origin. The effective scheme is https when the
// connection is TLS or X-Forwarded-Proto says https (the rule the dashboard
// session cookie's Secure flag uses); the effective host is the Host header or
// the first X-Forwarded-Host. A browser cannot set those headers on a
// cross-site form POST. Requests with neither header (older clients) are
// allowed: the session cookie remains the authentication.

// requireSameOriginDashboardMutation wraps a dashboard mutation handler with
// the same-origin check. A refused request gets 403 before the handler runs,
// so it has no side effect and records no audit event.
func requireSameOriginDashboardMutation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isSameOriginDashboardRequest(r) {
			log.Printf("[engram-cloud] refused cross-origin dashboard mutation: path=%s sec-fetch-site=%q origin=%q", r.URL.Path, r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin"))
			http.Error(w, "forbidden: cross-origin dashboard request", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func isSameOriginDashboardRequest(r *http.Request) bool {
	if site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); site != "" && !strings.EqualFold(site, "same-origin") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		return false
	}
	scheme := "http"
	if dashboardCookieSecure(r) {
		scheme = "https"
	}
	if !strings.EqualFold(parsed.Scheme, scheme) {
		return false
	}
	got := canonicalOriginHost(scheme, parsed.Host)
	for _, host := range []string{r.Host, firstForwardedHost(r)} {
		if host != "" && got == canonicalOriginHost(scheme, host) {
			return true
		}
	}
	return false
}

// canonicalOriginHost lowercases host and drops the scheme's default port.
func canonicalOriginHost(scheme, host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	defaultPort := ":80"
	if scheme == "https" {
		defaultPort = ":443"
	}
	return strings.TrimSuffix(host, defaultPort)
}

func firstForwardedHost(r *http.Request) string {
	first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ",")
	return strings.TrimSpace(first)
}

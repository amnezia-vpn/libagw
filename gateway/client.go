// Package gateway is a Qt-free port of the amnezia-client GatewayController:
// the encrypted request envelope, the HTTP transport and the proxy-bypass
// (failover) machinery for talking to the Amnezia API gateway.
//
// The package is pure Go with no cgo; the C ABI for embedding into C++,
// Swift, Kotlin and Dart hosts lives in the cabi package.
package gateway

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config carries everything a Client needs. GatewayEndpoint and
// PublicKeyPEM are mandatory; the rest have working defaults.
type Config struct {
	// GatewayEndpoint is the base URL of the API gateway, e.g.
	// "https://api.example.com".
	GatewayEndpoint string
	// PublicKeyPEM is the gateway RSA public key (PKIX PEM). It encrypts the
	// request envelope and derives the proxy-list decryption key.
	PublicKeyPEM []byte

	// S3PrimaryEndpoints / S3FallbackEndpoints host encrypted proxy-list
	// objects used when direct gateway access looks blocked.
	S3PrimaryEndpoints  []string
	S3FallbackEndpoints []string

	// IsDevEnvironment switches storage objects to plaintext JSON.
	IsDevEnvironment bool

	RequestTimeout      time.Duration // gateway POST, default 12s
	ProxyRequestTimeout time.Duration // POST through a proxy, defaults to RequestTimeout
	ProxyStorageTimeout time.Duration // storage GET, default 3s
	ProxyHealthTimeout  time.Duration // proxy health GET, default 1s

	// The timeouts above cover connect, TLS and the answer; name resolution
	// is bounded separately by DNSTimeout.
	DNSTimeout time.Duration // one name lookup, default 10s

	// HTTPClient overrides the transport (custom TLS, uTLS, tests). With a
	// host transport the shared DNS cache is not used.
	HTTPClient Doer
	// Resolver replaces the system resolver of the shared network stack.
	// Clients with the same Resolver share one DNS cache. Ignored when
	// HTTPClient is set.
	Resolver Resolver
	// OnBeforeRequest is invoked with the target host right before every
	// network attempt (gateway, storage, health checks, proxies) so hosts
	// can punch kill-switch exceptions. May be nil.
	OnBeforeRequest func(host string)
}

// PostOptions is the failover context of one request: which storage objects
// to probe when the direct path looks blocked.
type PostOptions struct {
	ServiceType     string
	UserCountryCode string
}

// Response is the gateway answer. Body is the API document as the gateway
// produced it, including its "http_status" and "message" fields on API
// errors; Post never interprets them.
type Response struct {
	Body  []byte
	Trace Trace
}

// Client talks to the Amnezia API gateway. It is safe for concurrent use.
// Post blocks for up to the full failover sequence; run it off the UI thread
// and use ctx for cancellation.
type Client struct {
	cfg  Config
	http Doer
	net  *netstack

	mu           sync.Mutex
	workingProxy string
	proxyLists   map[string][]string
}

const (
	defaultRequestTimeout      = 12 * time.Second
	defaultProxyStorageTimeout = 3 * time.Second
	defaultProxyHealthTimeout  = time.Second
	defaultDNSTimeout          = 10 * time.Second

	maxParallelHealth = 8

	healthPath = "lmbd-health"
)

// New creates a Client. Missing timeouts and HTTP client get defaults.
func New(cfg Config) *Client {
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.ProxyRequestTimeout <= 0 {
		cfg.ProxyRequestTimeout = cfg.RequestTimeout
	}
	if cfg.ProxyStorageTimeout <= 0 {
		cfg.ProxyStorageTimeout = defaultProxyStorageTimeout
	}
	if cfg.ProxyHealthTimeout <= 0 {
		cfg.ProxyHealthTimeout = defaultProxyHealthTimeout
	}
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = defaultDNSTimeout
	}
	c := &Client{cfg: cfg, http: cfg.HTTPClient, proxyLists: map[string][]string{}}
	if c.http == nil {
		c.net = stackFor(cfg.Resolver)
		c.http = &http.Client{Transport: c.net.transport}
	}
	return c
}

// Post sends one encrypted request to the gateway. endpoint is a path
// relative to the gateway base (e.g. "v1/services"), payload is the plain
// JSON document to encrypt. On a suspicious response the request is retried
// through the proxy pool resolved from the S3 storages.
//
// The returned error is either a *Error carrying an ErrorCode, or a
// *CancelledError (unwrapping to ctx.Err()) when the context was cancelled. Response.Body is set only on a nil error.
func (c *Client) Post(ctx context.Context, endpoint string, payload []byte, opts PostOptions) (Response, error) {
	began := time.Now()
	tr := &tracer{}
	// An already-cancelled caller wins over any other outcome.
	if ctx.Err() != nil {
		return Response{}, cancelledError(ctx, tr, began)
	}

	env, err := buildEnvelope(payload, c.cfg.PublicKeyPEM)
	if err != nil {
		tr.add("envelope: %s", err.Error())
		return Response{}, codeError(ConfigError, tr)
	}
	tr.add("request %s", env.requestID)
	if usesEnvironmentProxy(c.cfg.GatewayEndpoint) {
		tr.add("http proxy taken from the environment")
	}
	if ctx.Err() != nil {
		return Response{}, cancelledError(ctx, tr, began)
	}

	savedProxy := c.getWorkingProxy()
	c.prefetch(savedProxy, opts)
	var att attemptResult
	accepted := false
	if savedProxy != "" {
		att, accepted = c.tracedAttempt(ctx, tr, "saved proxy", savedProxy, endpoint, env, c.cfg.ProxyRequestTimeout)
		if ctx.Err() != nil {
			return Response{}, cancelledError(ctx, tr, began)
		}
		if !accepted {
			c.clearWorkingProxy(savedProxy)
			tr.add("saved proxy dropped")
		}
	}
	if !accepted {
		att, accepted = c.tracedAttempt(ctx, tr, "direct", c.cfg.GatewayEndpoint, endpoint, env, c.cfg.RequestTimeout)
		if ctx.Err() != nil {
			return Response{}, cancelledError(ctx, tr, began)
		}
	}
	if !accepted {
		att, _ = c.failover(ctx, tr, endpoint, env, opts, savedProxy, att)
		if ctx.Err() != nil {
			return Response{}, cancelledError(ctx, tr, began)
		}
	}

	if code := transportErrorCode(att); code != NoError {
		return Response{}, codeError(code, tr)
	}
	return Response{Body: att.body, Trace: tr.lines}, nil
}

func (c *Client) prefetch(savedProxy string, opts PostOptions) {
	if c.net == nil {
		return
	}
	targets := []string{c.cfg.GatewayEndpoint, savedProxy}
	targets = append(targets, c.cfg.S3PrimaryEndpoints...)
	targets = append(targets, c.cfg.S3FallbackEndpoints...)
	c.mu.Lock()
	targets = append(targets, c.proxyLists[proxyListKey(opts.ServiceType, opts.UserCountryCode)]...)
	c.mu.Unlock()

	hosts := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == "" || usesEnvironmentProxy(target) {
			continue
		}
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	c.net.prefetch(hosts, c.cfg.DNSTimeout)
}

func transportErrorCode(a attemptResult) ErrorCode {
	switch {
	case a.send.ssl:
		return SSLError
	case a.send.kind == transportTimeout || a.send.kind == transportCancelled:
		return TimeoutError
	case a.send.kind == transportConnError:
		return NetworkError
	case !a.decryptOK:
		return DecryptError
	}
	return NoError
}

type attemptResult struct {
	send      sendResult
	body      []byte
	decryptOK bool
}

func (c *Client) attempt(ctx context.Context, base, endpoint string, env envelope, timeout time.Duration) attemptResult {
	sr := c.send(ctx, http.MethodPost, joinURL(base, endpoint), env.body, timeout, env.requestID)
	out := attemptResult{send: sr, body: sr.body}
	if dec, err := aesDecryptCBC(sr.body, env.key, env.iv); err == nil {
		out.body, out.decryptOK = dec, true
	}
	return out
}

func (c *Client) tracedAttempt(ctx context.Context, tr *tracer, label, base, endpoint string, env envelope, timeout time.Duration) (attemptResult, bool) {
	att := c.attempt(ctx, base, endpoint, env, timeout)
	accepted := c.attemptAccepted(att)
	notes := att.send.notes()
	// Only the gateway address is logged: a foreign one points at DNS
	// poisoning. Storage and proxy addresses stay out of the trace.
	if label == "direct" {
		notes += att.send.addressNote()
	}
	if accepted {
		c.confirmAttempt(base, att)
		tr.add("%s: %s, accepted%s", label, att.describe(), notes)
	} else {
		tr.add("%s: %s, suspicious%s", label, att.describe(), notes)
	}
	return att, accepted
}

func (c *Client) confirmAttempt(base string, a attemptResult) {
	if a.decryptOK {
		c.confirm(base, a.send)
	}
}

func (c *Client) attemptAccepted(a attemptResult) bool {
	return !a.send.ssl && !shouldBypassProxy(a.send.kind, a.body, a.decryptOK)
}

func (c *Client) failover(ctx context.Context, tr *tracer, endpoint string, env envelope, opts PostOptions, savedProxy string, last attemptResult) (attemptResult, bool) {
	proxies := c.resolveProxyList(ctx, tr, opts)
	if savedProxy != "" {
		proxies = slices.DeleteFunc(proxies, func(p string) bool { return p == savedProxy })
	}
	rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })
	if len(proxies) == 0 {
		tr.add("failover: no proxies to try")
		return last, false
	}

	picked, order := c.pickHealthyProxy(ctx, tr, proxies)
	if picked >= 0 {
		att := c.attempt(ctx, proxies[picked], endpoint, env, c.cfg.ProxyRequestTimeout)
		if c.attemptAccepted(att) {
			c.confirmAttempt(proxies[picked], att)
			c.setWorkingProxy(proxies[picked])
			tr.add("proxy %d/%d: %s, accepted%s", picked+1, len(proxies), att.describe(), att.send.notes())
			return att, true
		}
		tr.add("proxy %d/%d: %s, rejected%s", picked+1, len(proxies), att.describe(), att.send.notes())
		last = att
	}

	for _, i := range order {
		if ctx.Err() != nil {
			return last, false
		}
		if i == picked {
			continue
		}
		att := c.attempt(ctx, proxies[i], endpoint, env, c.cfg.ProxyRequestTimeout)
		last = att
		if c.attemptAccepted(att) {
			c.confirmAttempt(proxies[i], att)
			c.setWorkingProxy(proxies[i])
			tr.add("proxy %d/%d: %s, accepted%s", i+1, len(proxies), att.describe(), att.send.notes())
			return att, true
		}
		tr.add("proxy %d/%d: %s, rejected%s", i+1, len(proxies), att.describe(), att.send.notes())
	}
	tr.add("failover: all %d proxies rejected", len(proxies))
	return last, false
}

func (c *Client) resolveProxyList(ctx context.Context, tr *tracer, opts PostOptions) []string {
	primary := append([]string(nil), c.cfg.S3PrimaryEndpoints...)
	fallback := append([]string(nil), c.cfg.S3FallbackEndpoints...)
	rand.Shuffle(len(primary), func(i, j int) { primary[i], primary[j] = primary[j], primary[i] })
	rand.Shuffle(len(fallback), func(i, j int) { fallback[i], fallback[j] = fallback[j], fallback[i] })

	key := proxyListKey(opts.ServiceType, opts.UserCountryCode)
	storageURLs := buildStorageURLs(primary, fallback, opts.ServiceType, opts.UserCountryCode)
	for i, storageURL := range storageURLs {
		if ctx.Err() != nil {
			return nil
		}
		sr := c.send(ctx, http.MethodGet, storageURL, nil, c.cfg.ProxyStorageTimeout, "")
		kind := storageKind(storageURL)
		if sr.kind != transportOK || sr.ssl || sr.status >= 300 {
			tr.add("storage %d/%d%s: %s%s", i+1, len(storageURLs), kind, sr.describe(), sr.notes())
			continue
		}
		list, err := decodeProxyList(sr.body, c.cfg.IsDevEnvironment, c.cfg.PublicKeyPEM)
		if err != nil {
			tr.add("storage %d/%d%s: %s, undecodable list%s", i+1, len(storageURLs), kind, sr.describe(), sr.notes())
			continue
		}
		tr.add("storage %d/%d%s: %s, %d proxies%s", i+1, len(storageURLs), kind, sr.describe(), len(list), sr.notes())
		if strings.HasPrefix(storageURL, "https://") {
			c.confirm(storageURL, sr)
		}
		c.mu.Lock()
		c.proxyLists[key] = append([]string(nil), list...)
		c.mu.Unlock()
		return list
	}

	c.mu.Lock()
	cached := append([]string(nil), c.proxyLists[key]...)
	c.mu.Unlock()
	tr.add("proxy list: %d proxies from cache", len(cached))
	return cached
}

func (c *Client) pickHealthyProxy(ctx context.Context, tr *tracer, proxies []string) (int, []int) {
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type check struct {
		index int
		ran   bool
		sr    sendResult
	}
	checks := make(chan check, len(proxies))
	slots := make(chan struct{}, maxParallelHealth)
	for i, proxy := range proxies {
		go func() {
			select {
			case slots <- struct{}{}:
			case <-hctx.Done():
				checks <- check{index: i}
				return
			}
			defer func() { <-slots }()
			if hctx.Err() != nil {
				checks <- check{index: i}
				return
			}
			checks <- check{index: i, ran: true, sr: c.send(hctx, http.MethodGet, joinURL(proxy, healthPath), nil, c.cfg.ProxyHealthTimeout, "")}
		}()
	}

	healthy := func(sr sendResult) bool { return sr.kind == transportOK && !sr.ssl && sr.status < 400 }
	results := make([]check, len(proxies))
	picked := -1
	for range proxies {
		r := <-checks
		results[r.index] = r
		if picked < 0 && r.ran && healthy(r.sr) {
			picked = r.index
			cancel()
		}
	}

	var good, unchecked, failed []int
	for i, r := range results {
		switch {
		case r.ran && healthy(r.sr):
			tr.add("health %d/%d: ok%s", i+1, len(proxies), r.sr.notes())
			good = append(good, i)
		case !r.ran || (r.sr.kind == transportCancelled && picked >= 0 && ctx.Err() == nil):
			unchecked = append(unchecked, i)
		default:
			tr.add("health %d/%d: %s%s", i+1, len(proxies), r.sr.describe(), r.sr.notes())
			failed = append(failed, i)
		}
	}
	return picked, slices.Concat(good, unchecked, failed)
}

func (c *Client) getWorkingProxy() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.workingProxy
}

func (c *Client) setWorkingProxy(proxy string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workingProxy = proxy
}

func (c *Client) clearWorkingProxy(proxy string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.workingProxy == proxy {
		c.workingProxy = ""
	}
}

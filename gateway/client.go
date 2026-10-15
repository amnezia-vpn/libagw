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
	"slices"
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

	// HTTPClient overrides the transport (custom TLS, uTLS, tests).
	HTTPClient Doer
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

	mu           sync.Mutex
	workingProxy string
	proxyLists   map[string][]string
}

const (
	defaultRequestTimeout      = 12 * time.Second
	defaultProxyStorageTimeout = 3 * time.Second
	defaultProxyHealthTimeout  = time.Second

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
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	return &Client{cfg: cfg, http: cfg.HTTPClient, proxyLists: map[string][]string{}}
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
		att = c.failover(ctx, tr, endpoint, env, opts, savedProxy, att)
		if ctx.Err() != nil {
			return Response{}, cancelledError(ctx, tr, began)
		}
	}

	if code := transportErrorCode(att); code != NoError {
		return Response{}, codeError(code, tr)
	}
	return Response{Body: att.body, Trace: tr.lines}, nil
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
	if accepted {
		tr.add("%s: %s, accepted", label, att.describe())
	} else {
		tr.add("%s: %s, suspicious", label, att.describe())
	}
	return att, accepted
}

func (c *Client) attemptAccepted(a attemptResult) bool {
	return !a.send.ssl && !shouldBypassProxy(a.send.kind, a.body, a.decryptOK)
}

func (c *Client) failover(ctx context.Context, tr *tracer, endpoint string, env envelope, opts PostOptions, savedProxy string, last attemptResult) attemptResult {
	proxies := c.resolveProxyList(ctx, tr, opts)
	if savedProxy != "" {
		proxies = slices.DeleteFunc(proxies, func(p string) bool { return p == savedProxy })
	}
	rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })
	if len(proxies) == 0 {
		tr.add("failover: no proxies to try")
		return last
	}

	picked, pickedIndex := c.pickHealthyProxy(ctx, tr, proxies)
	if picked != "" {
		att := c.attempt(ctx, picked, endpoint, env, c.cfg.ProxyRequestTimeout)
		if c.attemptAccepted(att) {
			c.setWorkingProxy(picked)
			tr.add("proxy %d/%d: %s, accepted", pickedIndex+1, len(proxies), att.describe())
			return att
		}
		tr.add("proxy %d/%d: %s, rejected", pickedIndex+1, len(proxies), att.describe())
		last = att
	}

	for i, proxy := range proxies {
		if ctx.Err() != nil {
			return last
		}
		if proxy == picked {
			continue
		}
		att := c.attempt(ctx, proxy, endpoint, env, c.cfg.ProxyRequestTimeout)
		last = att
		if c.attemptAccepted(att) {
			c.setWorkingProxy(proxy)
			tr.add("proxy %d/%d: %s, accepted", i+1, len(proxies), att.describe())
			return att
		}
		tr.add("proxy %d/%d: %s, rejected", i+1, len(proxies), att.describe())
	}
	tr.add("failover: all %d proxies rejected", len(proxies))
	return last
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
		if sr.kind != transportOK || sr.ssl || sr.status >= 300 {
			tr.add("storage %d/%d: %s", i+1, len(storageURLs), sr.describe())
			continue
		}
		list, err := decodeProxyList(sr.body, c.cfg.IsDevEnvironment, c.cfg.PublicKeyPEM)
		if err != nil {
			tr.add("storage %d/%d: %s, undecodable list", i+1, len(storageURLs), sr.describe())
			continue
		}
		tr.add("storage %d/%d: %s, %d proxies", i+1, len(storageURLs), sr.describe(), len(list))
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

func (c *Client) pickHealthyProxy(ctx context.Context, tr *tracer, proxies []string) (string, int) {
	for i, proxy := range proxies {
		if ctx.Err() != nil {
			return "", -1
		}
		sr := c.send(ctx, http.MethodGet, joinURL(proxy, healthPath), nil, c.cfg.ProxyHealthTimeout, "")
		if sr.kind == transportOK && !sr.ssl && sr.status < 400 {
			tr.add("health %d/%d: ok", i+1, len(proxies))
			return proxy, i
		}
		tr.add("health %d/%d: %s", i+1, len(proxies), sr.describe())
	}
	return "", -1
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

// Package gateway is a Qt-free port of the amnezia-client GatewayController:
// the encrypted request envelope, the HTTP transport and the proxy-bypass
// (failover) machinery for talking to the Amnezia API gateway.
//
// The package is pure Go with no cgo; the C ABI for embedding into C++,
// Swift, Kotlin and Dart hosts lives in the cabi package.
package gateway

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

// LogLevel of messages passed to Config.Logger.
type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarning
	LogError
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
	ProxyStorageTimeout time.Duration // storage GET, default 3s
	ProxyHealthTimeout  time.Duration // proxy health GET, default 1s

	// HTTPClient overrides the transport (custom TLS, uTLS, tests).
	HTTPClient Doer
	// Logger receives diagnostic messages; may be nil. Messages never carry
	// endpoint addresses: hosts route them into application logs that users
	// export and share, and these are censorship-bypass endpoints.
	Logger func(LogLevel, string)
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

// Response is the (decrypted) gateway response body. It may be non-empty
// even when Post also returns an *Error — e.g. captcha challenges arrive in
// the body of an ApiCaptchaRequiredError response.
type Response struct {
	Body []byte
	// Status is the outer HTTP status of the answering attempt (0 when no
	// attempt produced a response). Error mapping already folds the status
	// into the returned ErrorCode; it is exposed for callers that need to
	// tell apart gateway conditions the shared codes collapse (e.g. the b2b
	// SDK's 403/502/503 handling).
	Status int
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

func (c *Client) log(level LogLevel, msg string) {
	if c.cfg.Logger != nil {
		c.cfg.Logger(level, msg)
	}
}

// Post sends one encrypted request to the gateway. endpoint is a path
// relative to the gateway base (e.g. "v1/services"), payload is the plain
// JSON document to encrypt. On a suspicious response the request is retried
// through the proxy pool resolved from the S3 storages.
//
// The returned error is either a *Error carrying an ErrorCode, or ctx.Err()
// when the context was cancelled. Response.Body may be meaningful in both
// cases.
func (c *Client) Post(ctx context.Context, endpoint string, payload []byte, opts PostOptions) (Response, error) {
	// An already-cancelled caller wins over any other outcome.
	if ctx.Err() != nil {
		return Response{}, ctx.Err()
	}

	env, err := buildEnvelope(payload, c.cfg.PublicKeyPEM)
	if err != nil {
		c.log(LogWarning, "request build failed: "+err.Error())
		if isInvalidKeyErr(err) {
			return Response{}, codeError(ApiMissingAgwPublicKey)
		}
		return Response{}, codeError(ApiConfigDecryptionError)
	}
	if ctx.Err() != nil {
		return Response{}, ctx.Err()
	}

	base := c.getWorkingProxy()
	viaProxy := base != ""
	if !viaProxy {
		base = c.cfg.GatewayEndpoint
	}
	c.log(LogDebug, "direct attempt")
	att := c.attempt(ctx, base, endpoint, env)
	if ctx.Err() != nil {
		return Response{Body: att.body, Status: att.status}, ctx.Err()
	}

	if !att.ssl && shouldBypassProxy(att.kind, att.body, att.decryptOK) {
		c.log(LogInfo, "direct response suspicious - running proxy failover")
		att = c.failover(ctx, endpoint, env, opts, att)
		if ctx.Err() != nil {
			return Response{Body: att.body, Status: att.status}, ctx.Err()
		}
	}

	if code := mapResponseError(att.ssl, att.kind, att.status, att.body); code != NoError {
		c.log(LogWarning, "post finished with error: "+ErrorText(code))
		return Response{Body: att.body, Status: att.status}, codeError(code)
	}
	if !att.decryptOK {
		c.log(LogError, "response decryption failed")
		return Response{Body: att.body, Status: att.status}, codeError(ApiConfigDecryptionError)
	}
	return Response{Body: att.body, Status: att.status}, nil
}

type attemptResult struct {
	kind      transportErrorKind
	ssl       bool
	status    int
	body      []byte // decrypted when decryptOK, raw otherwise
	decryptOK bool
}

func (c *Client) attempt(ctx context.Context, base, endpoint string, env envelope) attemptResult {
	sr := c.send(ctx, http.MethodPost, joinURL(base, endpoint), env.body, c.cfg.RequestTimeout, newRequestID())
	out := attemptResult{kind: sr.kind, ssl: sr.ssl, status: sr.status, body: sr.body}
	if dec, err := aesDecryptCBC(sr.body, env.key, env.iv); err == nil {
		out.body = dec
		out.decryptOK = true
	}
	return out
}

func (c *Client) attemptAccepted(a attemptResult) bool {
	return !a.ssl && !shouldBypassProxy(a.kind, a.body, a.decryptOK)
}

func (c *Client) failover(ctx context.Context, endpoint string, env envelope, opts PostOptions, last attemptResult) attemptResult {
	proxies := c.resolveProxyList(ctx, opts)
	rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })

	// The proxy used for the direct attempt (if any) just failed: drop it.
	c.setWorkingProxy("")

	if picked := c.pickHealthyProxy(ctx, proxies); picked != "" {
		c.log(LogDebug, "healthy proxy found")
		att := c.attempt(ctx, picked, endpoint, env)
		if c.attemptAccepted(att) {
			c.setWorkingProxy(picked)
			return att
		}
		last = att
	}

	for i, proxy := range proxies {
		if ctx.Err() != nil {
			return last
		}
		att := c.attempt(ctx, proxy, endpoint, env)
		last = att
		if c.attemptAccepted(att) {
			c.setWorkingProxy(proxy)
			c.log(LogInfo, fmt.Sprintf("proxy %d/%d answered", i+1, len(proxies)))
			return att
		}
		c.log(LogDebug, fmt.Sprintf("proxy %d/%d unreachable", i+1, len(proxies)))
	}
	c.log(LogInfo, "failover exhausted all proxies")
	return last
}

func (c *Client) resolveProxyList(ctx context.Context, opts PostOptions) []string {
	primary := append([]string(nil), c.cfg.S3PrimaryEndpoints...)
	fallback := append([]string(nil), c.cfg.S3FallbackEndpoints...)
	rand.Shuffle(len(primary), func(i, j int) { primary[i], primary[j] = primary[j], primary[i] })
	rand.Shuffle(len(fallback), func(i, j int) { fallback[i], fallback[j] = fallback[j], fallback[i] })

	key := proxyListKey(opts.ServiceType, opts.UserCountryCode)
	for _, storageURL := range buildStorageURLs(primary, fallback, opts.ServiceType, opts.UserCountryCode) {
		if ctx.Err() != nil {
			return nil
		}
		sr := c.send(ctx, http.MethodGet, storageURL, nil, c.cfg.ProxyStorageTimeout, "")
		if sr.kind != transportOK || sr.ssl || sr.status >= 300 {
			c.log(LogDebug, "storage unreachable, trying next")
			continue
		}
		list, err := decodeProxyList(sr.body, c.cfg.IsDevEnvironment, c.cfg.PublicKeyPEM)
		if err != nil {
			c.log(LogDebug, "storage object decode failed, trying next")
			continue
		}
		c.mu.Lock()
		c.proxyLists[key] = append([]string(nil), list...)
		c.mu.Unlock()
		return list
	}

	c.mu.Lock()
	cached := append([]string(nil), c.proxyLists[key]...)
	c.mu.Unlock()
	c.log(LogDebug, "all storages unreachable, using cached proxy list")
	return cached
}

func (c *Client) pickHealthyProxy(ctx context.Context, proxies []string) string {
	for _, proxy := range proxies {
		if ctx.Err() != nil {
			return ""
		}
		sr := c.send(ctx, http.MethodGet, joinURL(proxy, healthPath), nil, c.cfg.ProxyHealthTimeout, "")
		if sr.kind == transportOK && !sr.ssl && sr.status < 400 {
			return proxy
		}
	}
	return ""
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

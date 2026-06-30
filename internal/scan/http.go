package scan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// retryBackoff is the pause before a retryable HTTP error is retried. It is a
// package-level variable so tests can shorten it and avoid sleeping 500ms.
var retryBackoff = 500 * time.Millisecond

// ProbeURL probes a single URL with a fresh client. It is kept for backward
// compatibility (e.g. http_test.go); the concurrent path uses probeURLs with a
// shared client via probeURLWithClient.
func ProbeURL(ctx context.Context, rawURL string, timeout time.Duration, proxy string) model.Service {
	return probeURLWithClient(ctx, httpClient(timeout, proxy), rawURL)
}

// probeURLWithClient probes a single URL using the given (shared) client. On a
// retryable network error (timeout, refused, EOF) it retries once after
// retryBackoff. A 4xx/5xx response is NOT an error — it returns the status.
// NormalizeURL failure now produces a structurally complete Service.
func probeURLWithClient(ctx context.Context, client *http.Client, rawURL string) model.Service {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		// B.5: complete the struct so failed probes still render as a full row.
		return model.Service{Host: rawURL, Protocol: "http", URL: rawURL, Service: "WEB应用", Error: err.Error()}
	}
	u, _ := url.Parse(normalized)
	svc := model.Service{
		Host:     u.Hostname(),
		Port:     portFromURL(u),
		Protocol: "http",
		Scheme:   u.Scheme,
		URL:      normalized,
		Service:  "WEB应用",
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		svc.IP = ip.String()
	}

	do := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalized, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "SpringX-Scanner/0.1")
		return client.Do(req)
	}
	resp, err := do()
	if err != nil && isRetryableNetError(ctx, err) {
		select {
		case <-time.After(retryBackoff):
		case <-ctx.Done():
		}
		resp, err = do()
	}
	if err != nil {
		svc.Error = err.Error()
		return svc
	}
	defer resp.Body.Close()

	svc.StatusCode = resp.StatusCode
	svc.Server = resp.Header.Get("Server")
	svc.ContentType = resp.Header.Get("Content-Type")
	// net/http reports ContentLength == -1 for chunked/unknown-length responses;
	// the model field's omitempty only drops 0, so the >0 guard prevents a "-1"
	// from leaking into the JSON/event stream.
	if resp.ContentLength > 0 {
		svc.ContentLength = resp.ContentLength
	}
	svc.Location = resp.Header.Get("Location")
	if resp.TLS != nil {
		svc.TLS = tlsSummary(resp.TLS)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	svc.Title = extractTitle(string(body))
	svc.Technologies, svc.FingerprintSources = detectTechnologies(resp.Header, string(body))
	svc.FaviconHash = faviconHash(ctx, client, normalized)
	return svc
}

// isRetryableNetError reports whether err is a transient network failure worth
// one retry. User cancellation (context.Canceled) is never retried.
func isRetryableNetError(ctx context.Context, err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return false
}

// probeURLs probes a list of URLs concurrently, mirroring the tcp.go ScanPorts
// worker-pool pattern. onResult is invoked from worker goroutines (Emitter and
// Logf are mutex-safe). It does NOT emit target_discovered — the caller does
// that before invoking, so the "discovered" semantic is preserved.
func probeURLs(ctx context.Context, urls []string, concurrency int, client *http.Client, onResult func(model.Service)) []model.Service {
	jobs := make(chan string)
	results := make(chan model.Service)
	var wg sync.WaitGroup

	workerCount := concurrency
	if workerCount < 1 {
		workerCount = 1
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				svc := probeURLWithClient(ctx, client, rawURL)
				select {
				case results <- svc:
				case <-ctx.Done():
					return
				}
				if onResult != nil {
					onResult(svc)
				}
			}
		}()
	}

	// Producer: honor ctx cancellation, then close jobs so workers exit.
	go func() {
		defer close(jobs)
		for _, u := range urls {
			select {
			case <-ctx.Done():
				return
			case jobs <- u:
			}
		}
	}()

	// Closer: once all workers are done, close results so the drain loop exits.
	go func() {
		wg.Wait()
		close(results)
	}()

	var services []model.Service
	for svc := range results {
		services = append(services, svc)
	}
	return services
}

func ProbeHTTPService(ctx context.Context, host string, port int, timeout time.Duration, proxy string) model.Service {
	schemes := []string{"http"}
	if likelyHTTPS(port) {
		schemes = []string{"https", "http"}
	}
	client := httpClient(timeout, proxy)
	var last model.Service
	for _, scheme := range schemes {
		raw := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		if defaultPort(scheme, port) {
			raw = fmt.Sprintf("%s://%s/", scheme, host)
		}
		svc := probeURLWithClient(ctx, client, raw)
		if svc.StatusCode > 0 || svc.Title != "" || svc.Server != "" {
			return svc
		}
		last = svc
	}
	if last.Host == "" {
		last.Host = host
		last.Port = port
	}
	last.Protocol = serviceName(port)
	last.Service = last.Protocol
	return last
}

// httpClient builds a per-call client (kept for ProbeURL/ProbeHTTPService
// compatibility). The concurrent path uses sharedHTTPClient instead.
func httpClient(timeout time.Duration, proxyValue string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		Proxy:               http.ProxyFromEnvironment,
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 1,
	}
	if proxyValue != "" {
		if proxyURL, err := url.Parse(proxyValue); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// sharedHTTPClient builds one client reused by all probeURLs workers, so the
// keep-alive connection pool is actually shared. Idle-connection limits scale
// with concurrency to avoid starving a busy host.
func sharedHTTPClient(timeout time.Duration, proxyValue string, concurrency int) *http.Client {
	maxPerHost := concurrency
	if maxPerHost < 2 {
		maxPerHost = 2
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		Proxy:               http.ProxyFromEnvironment,
		DisableKeepAlives:   false,
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: maxPerHost,
	}
	if proxyValue != "" {
		if proxyURL, err := url.Parse(proxyValue); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func extractTitle(body string) string {
	matches := titleRE.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	title := strings.Join(strings.Fields(htmlUnescape(matches[1])), " ")
	if len(title) > 160 {
		title = title[:160]
	}
	return title
}

func htmlUnescape(value string) string {
	replacer := strings.NewReplacer("&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#39;", "'", "&quot;", `"`)
	return replacer.Replace(value)
}

func detectTechnologies(header http.Header, body string) ([]string, []string) {
	var tech []string
	var sources []string
	server := strings.ToLower(header.Get("Server"))
	powered := strings.ToLower(header.Get("X-Powered-By"))
	generator := strings.ToLower(header.Get("X-Generator"))
	cookie := strings.ToLower(strings.Join(header.Values("Set-Cookie"), ";"))
	lowerBody := strings.ToLower(body)
	rules := []struct {
		name    string
		needles []string
		fields  map[string]string
	}{
		{"Nginx", []string{"nginx"}, map[string]string{"server": server}},
		{"Apache", []string{"apache"}, map[string]string{"server": server}},
		{"IIS", []string{"microsoft-iis", "iis"}, map[string]string{"server": server}},
		{"OpenResty", []string{"openresty"}, map[string]string{"server": server, "body": lowerBody}},
		{"Cloudflare", []string{"cloudflare", "__cf_bm", "cf-ray"}, map[string]string{"server": server, "cookie": cookie, "body": lowerBody}},
		{"PHP", []string{"php", "phpsessid"}, map[string]string{"powered": powered, "cookie": cookie, "body": lowerBody}},
		{"ASP.NET", []string{"asp.net", "aspxauth"}, map[string]string{"powered": powered, "cookie": cookie, "body": lowerBody}},
		{"Java", []string{"jsessionid", "x-java"}, map[string]string{"cookie": cookie, "powered": powered}},
		{"Spring", []string{"spring", "whitelabel error page"}, map[string]string{"body": lowerBody, "powered": powered}},
		{"WordPress", []string{"wp-content", "wp-includes", "wordpress"}, map[string]string{"body": lowerBody, "generator": generator}},
		{"Drupal", []string{"drupal", "x-drupal-cache"}, map[string]string{"body": lowerBody, "generator": generator}},
		{"Joomla", []string{"joomla"}, map[string]string{"body": lowerBody, "generator": generator}},
		{"ThinkPHP", []string{"thinkphp"}, map[string]string{"body": lowerBody, "powered": powered}},
		{"Laravel", []string{"laravel", "xsrftoken", "xsrf-token"}, map[string]string{"body": lowerBody, "cookie": cookie}},
		{"Vue", []string{"vue", "__vue__"}, map[string]string{"body": lowerBody}},
		{"React", []string{"react", "__react", "data-reactroot"}, map[string]string{"body": lowerBody}},
		{"Angular", []string{"ng-version", "angular"}, map[string]string{"body": lowerBody}},
		{"jQuery", []string{"jquery"}, map[string]string{"body": lowerBody}},
		{"Bootstrap", []string{"bootstrap"}, map[string]string{"body": lowerBody}},
	}
	for _, rule := range rules {
		for source, haystack := range rule.fields {
			if haystack == "" {
				continue
			}
			for _, needle := range rule.needles {
				if strings.Contains(haystack, needle) {
					tech = appendUnique(tech, rule.name)
					sources = appendUnique(sources, rule.name+":"+source)
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return tech, sources
}

// faviconHash fetches /favicon.ico and returns its murmur3 hash. It accepts the
// shared client so the concurrent path reuses the connection pool.
func faviconHash(ctx context.Context, client *http.Client, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Path = "/favicon.ico"
	u.RawQuery = ""
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "SpringX-Scanner/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(body) == 0 {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	return fmt.Sprintf("%d", murmur3([]byte(encoded), 0))
}

func murmur3(data []byte, seed uint32) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = bitsRotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = bitsRotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bitsRotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}

func bitsRotateLeft32(x uint32, k int) uint32 {
	return (x << k) | (x >> (32 - k))
}

func portFromURL(u *url.URL) int {
	if value := u.Port(); value != "" {
		var port int
		_, _ = fmt.Sscanf(value, "%d", &port)
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func likelyHTTPS(port int) bool {
	switch port {
	case 443, 8443, 9443, 10443, 12443:
		return true
	default:
		return false
	}
}

func defaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

func tlsSummary(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	version := map[uint16]string{
		tls.VersionTLS10: "TLS1.0",
		tls.VersionTLS11: "TLS1.1",
		tls.VersionTLS12: "TLS1.2",
		tls.VersionTLS13: "TLS1.3",
	}[state.Version]
	if version == "" {
		version = fmt.Sprintf("TLS-%x", state.Version)
	}
	if len(state.PeerCertificates) > 0 {
		return version + " " + state.PeerCertificates[0].Issuer.CommonName
	}
	return version
}

func serviceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 465, 587:
		return "smtp"
	case 53:
		return "dns"
	case 110, 995:
		return "pop3"
	case 143, 993:
		return "imap"
	case 389, 636:
		return "ldap"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 9200, 9300:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 27017, 27018, 27019:
		return "mongodb"
	default:
		if port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 8008 || port == 8888 || port == 9000 || port == 9090 {
			return "http"
		}
		return "tcp"
	}
}

package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

func ProbeURL(ctx context.Context, rawURL string, timeout time.Duration, proxy string) model.Service {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		return model.Service{Host: rawURL, Error: err.Error()}
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

	client := httpClient(timeout, proxy)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalized, nil)
	if err != nil {
		svc.Error = err.Error()
		return svc
	}
	req.Header.Set("User-Agent", "SpringX-Scanner/0.1")
	resp, err := client.Do(req)
	if err != nil {
		svc.Error = err.Error()
		return svc
	}
	defer resp.Body.Close()

	svc.StatusCode = resp.StatusCode
	svc.Server = resp.Header.Get("Server")
	if resp.TLS != nil {
		svc.TLS = tlsSummary(resp.TLS)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	svc.Title = extractTitle(string(body))
	svc.Technologies = detectTechnologies(resp.Header, string(body))
	return svc
}

func ProbeHTTPService(ctx context.Context, host string, port int, timeout time.Duration, proxy string) model.Service {
	schemes := []string{"http"}
	if likelyHTTPS(port) {
		schemes = []string{"https", "http"}
	}
	var last model.Service
	for _, scheme := range schemes {
		raw := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		if defaultPort(scheme, port) {
			raw = fmt.Sprintf("%s://%s/", scheme, host)
		}
		svc := ProbeURL(ctx, raw, timeout, proxy)
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

func detectTechnologies(header http.Header, body string) []string {
	var tech []string
	server := strings.ToLower(header.Get("Server"))
	powered := strings.ToLower(header.Get("X-Powered-By"))
	lowerBody := strings.ToLower(body)
	for name, needle := range map[string]string{
		"Nginx": "nginx", "Apache": "apache", "IIS": "microsoft-iis",
		"PHP": "php", "ASP.NET": "asp.net", "Spring": "spring",
		"Vue": "vue", "React": "react", "jQuery": "jquery",
	} {
		if strings.Contains(server, needle) || strings.Contains(powered, needle) || strings.Contains(lowerBody, needle) {
			tech = append(tech, name)
		}
	}
	return tech
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

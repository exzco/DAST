// Package engine provides core scanning and service identification logic.
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"distributed-scanner/internal/model"

	nmap "github.com/Ullaakut/nmap/v3"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	hrefRegex    = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'>\s#]+)["']`)
	apiPathRegex = regexp.MustCompile(`(?i)["'](/(?:api|v[0-9]|rest|admin|user|auth|login|manage|health|actuator|metrics|status)[a-zA-Z0-9_\-/\.]*)["']`)
)

type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	RawHeader  http.Header
	Body       string
	DurationMs int64
}

type HTTPClient struct {
	client *http.Client
}

func NewHTTPClient(timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}
	return &HTTPClient{
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (c *HTTPClient) Do(ctx context.Context, method, targetURL string, headers map[string]string, body string) (*HTTPResponse, error) {
	start := time.Now()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DAST-Scanner/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()

	limitReader := io.LimitReader(resp.Body, 5*1024*1024) 
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	respHeaders := make(map[string]string)
	for k, vals := range resp.Header {
		respHeaders[k] = strings.Join(vals, "; ")
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		RawHeader:  resp.Header,
		Body:       string(bodyBytes),
		DurationMs: duration,
	}, nil
}

// 提取 api 路径，从前端 js 
func ExtractLinks(baseURLStr string, body string) []string {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil
	}

	foundMap := make(map[string]bool)
	var links []string

	// 1.提取 href, src, action
	matches := hrefRegex.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			rawPath := strings.TrimSpace(m[1])
			if cleanPath := normalizeExtractedPath(baseURL, rawPath); cleanPath != "" {
				if !foundMap[cleanPath] {
					foundMap[cleanPath] = true
					links = append(links, cleanPath)
				}
			}
		}
	}

	// 2. 提取 api 
	apiMatches := apiPathRegex.FindAllStringSubmatch(body, -1)
	for _, am := range apiMatches {
		if len(am) > 1 {
			p := strings.TrimSpace(am[1])
			if !foundMap[p] && strings.HasPrefix(p, "/") {
				foundMap[p] = true
				links = append(links, p)
			}
		}
	}
	return links
}

func normalizeExtractedPath(baseURL *url.URL, raw string) string {
	if strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err == nil && u.Host == baseURL.Host {
			return u.RequestURI()
		}
		return ""
	}
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	return "/" + raw
}


type TLSAnalyzer struct {
	dialTimeout time.Duration
}

func NewTLSAnalyzer(timeout time.Duration) *TLSAnalyzer {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &TLSAnalyzer{dialTimeout: timeout}
}

func (a *TLSAnalyzer) Analyze(ctx context.Context, host string, port int) (*model.TLSInfo, error) {
	if port <= 0 {
		port = 443
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: a.dialTimeout}
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, conf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	defer tlsConn.Close()

	cs := tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	cert := cs.PeerCertificates[0]
	now := time.Now()
	isExpired := now.Before(cert.NotBefore) || now.After(cert.NotAfter)

	var alpnList []string
	if cs.NegotiatedProtocol != "" {
		alpnList = append(alpnList, cs.NegotiatedProtocol)
	}

	return &model.TLSInfo{
		Version:     tlsVersionToString(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		SubjectCN:   cert.Subject.CommonName,
		DNSNames:    cert.DNSNames,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		IsExpired:   isExpired,
		ALPN:        alpnList,
	}, nil
}

func tlsVersionToString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", ver)
	}
}

// bin service ，由 nmap -sV 进行服务识别
type NmapServiceScanner struct{}

func NewNmapServiceScanner() *NmapServiceScanner {
	return &NmapServiceScanner{}
}

func (s *NmapServiceScanner) DetectServices(ctx context.Context, host string, ports []int) map[int]model.Service {
	result := make(map[int]model.Service)
	if len(ports) == 0 {
		return result
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	portRange := strings.Join(portStrs, ",")

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(portRange),
		nmap.WithServiceInfo(), 
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
	)
	if err != nil {
		return result
	}

	nmapRes, _, err := scanner.Run()
	if err != nil || nmapRes == nil {
		return result
	}

	for _, h := range nmapRes.Hosts {
		for _, p := range h.Ports {
			if p.State.State == "open" {
				svcName := strings.ToLower(p.Service.Name)
				prodName := strings.ToLower(p.Service.Product)
				result[int(p.ID)] = model.Service{
					ID:         model.NewUUID(),
					Host:       host,
					Port:       int(p.ID),
					Transport:  "tcp",
					Protocol:   svcName,
					Product:    prodName,
					Version:    p.Service.Version,
					Confidence: model.ConfidenceCertain,
					ObservedAt: time.Now().UTC(),
				}
			}
		}
	}
	return result
}


// Wappalyzer + Custom FingerprintEngine ，先使用 wappalyzer ，再使用自定义指纹识别
type HTTPRule struct {
	Tags    []string `json:"tags"`
	Headers []string `json:"headers,omitempty"`
	Body    []string `json:"body,omitempty"`
}

type BannerRule struct {
	Tags      []string `json:"tags"`
	Prefix    string   `json:"prefix,omitempty"`
	HexPrefix string   `json:"hex_prefix,omitempty"`
}

type FingerprintRuleSet struct {
	HTTPRules   []HTTPRule   `json:"http_rules"`
	BannerRules []BannerRule `json:"banner_rules"`
}

type FingerprintEngine struct {
	mu         sync.RWMutex
	rules      FingerprintRuleSet
	wappalyzer *wappalyzer.Wappalyze
}

func NewFingerprintEngine(rulesPath string) *FingerprintEngine {
	engine := &FingerprintEngine{}

	// Initialize Wappalyzer
	if wapp, err := wappalyzer.New(); err == nil {
		engine.wappalyzer = wapp
	}

	if rulesPath == "" {
		rulesPath = "data/fingerprints.json"
	}

	searchPaths := []string{
		rulesPath,
		"./data/fingerprints.json",
		"../data/fingerprints.json",
		"../../data/fingerprints.json",
	}

	for _, p := range searchPaths {
		if abs, err := filepath.Abs(p); err == nil {
			if data, err := os.ReadFile(abs); err == nil {
				var loaded FingerprintRuleSet
				if json.Unmarshal(data, &loaded) == nil && (len(loaded.HTTPRules) > 0 || len(loaded.BannerRules) > 0) {
					engine.rules = loaded
					break
				}
			}
		}
	}
	return engine
}

// 探测函数
func (fe *FingerprintEngine) DetectWebTechnologies(rawHeader http.Header, headers map[string]string, body string) (tags []string, product string) {
	tagSet := make(map[string]bool)

	// 1. Wappalyzer 探测
	if fe.wappalyzer != nil && rawHeader != nil {
		wappTechs := fe.wappalyzer.Fingerprint(rawHeader, []byte(body))
		for tech := range wappTechs {
			lowerTech := strings.ToLower(tech)
			tagSet[lowerTech] = true
			if product == "" {
				product = lowerTech
			}
		}
	}

	// 2. Custom FingerprintEngine  探测
	customTags, customProd := fe.MatchHTTP(headers, body)
	for _, t := range customTags {
		tagSet[t] = true
	}
	if product == "" && customProd != "" {
		product = customProd
	}

	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags, product
}

func (fe *FingerprintEngine) MatchHTTP(headers map[string]string, body string) (matchedTags []string, product string) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	tagSet := make(map[string]bool)
	lowerBody := strings.ToLower(body)

	for _, rule := range fe.rules.HTTPRules {
		matched := true

		if len(rule.Headers) > 0 {
			headerMatched := false
			for _, reqHdr := range rule.Headers {
				if strings.Contains(reqHdr, ":") {
					parts := strings.SplitN(reqHdr, ":", 2)
					reqKey := strings.TrimSpace(parts[0])
					reqVal := strings.ToLower(strings.TrimSpace(parts[1]))

					for k, v := range headers {
						if strings.EqualFold(k, reqKey) && strings.Contains(strings.ToLower(v), reqVal) {
							headerMatched = true
							break
						}
					}
				} else {
					for k := range headers {
						if strings.EqualFold(k, reqHdr) {
							headerMatched = true
							break
						}
					}
				}
				if headerMatched {
					break
				}
			}
			if !headerMatched {
				matched = false
			}
		}

		if matched && len(rule.Body) > 0 {
			bodyMatched := false
			for _, b := range rule.Body {
				if strings.Contains(lowerBody, strings.ToLower(b)) {
					bodyMatched = true
					break
				}
			}
			if !bodyMatched {
				matched = false
			}
		}

		if matched {
			for _, t := range rule.Tags {
				tagSet[t] = true
				if product == "" {
					product = t
				}
			}
		}
	}

	for t := range tagSet {
		matchedTags = append(matchedTags, t)
	}
	return matchedTags, product
}

func (fe *FingerprintEngine) MatchBanner(banner []byte) (matchedTags []string, product string) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	tagSet := make(map[string]bool)
	bannerStr := string(banner)

	for _, rule := range fe.rules.BannerRules {
		matched := false

		if rule.Prefix != "" && strings.HasPrefix(bannerStr, rule.Prefix) {
			matched = true
		}

		if !matched && rule.HexPrefix != "" {
			if expectedBytes, err := hex.DecodeString(rule.HexPrefix); err == nil {
				if bytes.HasPrefix(banner, expectedBytes) {
					matched = true
				}
			}
		}

		if matched {
			for _, t := range rule.Tags {
				tagSet[t] = true
				if product == "" {
					product = t
				}
			}
		}
	}

	for t := range tagSet {
		matchedTags = append(matchedTags, t)
	}
	return matchedTags, product
}

func (fe *FingerprintEngine) GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return buf[:n], nil
	}

	probePayload := []byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")
	_, _ = conn.Write(probePayload)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	n, err = conn.Read(buf)
	if err == nil && n > 0 {
		return buf[:n], nil
	}

	return nil, err
}

func (fe *FingerprintEngine) IdentifyService(ctx context.Context, host string, port int, transport string) (protocol, product string, tags []string, confidence model.Confidence) {
	if transport == "tcp" {
		banner, err := fe.GrabBanner(ctx, host, port, 400*time.Millisecond)
		if err == nil && len(banner) > 0 {
			if bytes.HasPrefix(banner, []byte("HTTP/")) {
				return "http", "", []string{"http"}, model.ConfidenceFirm
			}
			matchedTags, prod := fe.MatchBanner(banner)
			if len(matchedTags) > 0 {
				proto := matchedTags[0]
				return proto, prod, matchedTags, model.ConfidenceCertain
			}
		}
	}

	switch port {
	case 80, 8080, 8081, 8082, 8083, 8084, 8085, 9200, 3000, 5601, 7890:
		return "http", "", []string{"http"}, model.ConfidenceFirm
	case 443, 8443:
		return "https", "", []string{"https"}, model.ConfidenceFirm
	case 22:
		return "ssh", "openssh", []string{"ssh"}, model.ConfidenceTentative
	case 135:
		return "msrpc", "microsoft-rpc", []string{"msrpc"}, model.ConfidenceTentative
	case 445:
		return "smb", "microsoft-ds", []string{"smb"}, model.ConfidenceTentative
	case 3306, 33060:
		return "mysql", "mysql", []string{"mysql"}, model.ConfidenceTentative
	case 6379, 6380:
		return "redis", "redis", []string{"redis"}, model.ConfidenceTentative
	case 27017:
		return "mongodb", "mongodb", []string{"mongodb"}, model.ConfidenceTentative
	case 5432:
		return "postgres", "postgresql", []string{"postgres"}, model.ConfidenceTentative
	case 1433:
		return "mssql", "microsoft-sql-server", []string{"mssql"}, model.ConfidenceTentative
	case 1521:
		return "oracle", "oracle-tns", []string{"oracle"}, model.ConfidenceTentative
	case 21:
		return "ftp", "ftp", []string{"ftp"}, model.ConfidenceTentative
	case 25, 465, 587:
		return "smtp", "smtp", []string{"smtp"}, model.ConfidenceTentative
	default:
		return "unknown", "", nil, model.ConfidenceTentative
	}
}

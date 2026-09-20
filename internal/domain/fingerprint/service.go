// package fingerprint provides core scanning and service identification logic.
package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"distributed-scanner/internal/infra/network"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chainreactors/fingers"
	rawfingers "github.com/chainreactors/fingers/fingers"

	"distributed-scanner/internal/model"

	nmap "github.com/Ullaakut/nmap/v3"
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
	RawBytes   []byte
	DurationMs int64
}

type HTTPClient struct {
	client *http.Client
}

func NewHTTPClient(timeout time.Duration) *HTTPClient {
	c := network.NewHTTPClient(timeout)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &HTTPClient{
		client: c,
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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) D-Scanner/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()

	// Limit to 256KB to prevent Regex CPU denial of service in fingers engine
	limitReader := io.LimitReader(resp.Body, 256*1024)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	respHeaders := make(map[string]string)
	var rawResp bytes.Buffer
	rawResp.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)))
	for k, vals := range resp.Header {
		respHeaders[k] = strings.Join(vals, "; ")
		for _, v := range vals {
			rawResp.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(bodyBytes)

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		RawHeader:  resp.Header,
		Body:       string(bodyBytes),
		RawBytes:   rawResp.Bytes(),
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
		timeout = 800 * time.Millisecond
	}
	return &TLSAnalyzer{dialTimeout: timeout}
}

func (a *TLSAnalyzer) Analyze(ctx context.Context, host string, port int) (*model.TLSInfo, error) {
	if port <= 0 {
		port = 443
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := network.NewDialer(a.dialTimeout)
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	// Enforce a strict deadline for the TLS handshake so it doesn't block forever
	rawConn.SetDeadline(time.Now().Add(a.dialTimeout))

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

	nmapCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmapCtx,
		nmap.WithTargets(host),
		nmap.WithPorts(portRange),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(5),
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

// // Fingers Engine Integration
type FingerprintEngine struct {
	engine *fingers.Engine
}

func NewFingerprintEngine() *FingerprintEngine {
	engine, err := fingers.NewEngine()
	if err != nil {
		fmt.Printf("[-] Failed to initialize fingers engine: %v\n", err)
	}
	return &FingerprintEngine{
		engine: engine,
	}
}

// DetectWebTechnologies identifies web components using fingers.
func (fe *FingerprintEngine) DetectWebTechnologies(resp *HTTPResponse) (tags []string, product string, vulns []string) {
	if fe.engine == nil || resp == nil || len(resp.RawBytes) == 0 {
		return
	}

	// Slice to max 128KB for regex scanning to prevent CPU freeze
	scanBytes := resp.RawBytes
	if len(scanBytes) > 128*1024 {
		scanBytes = scanBytes[:128*1024]
	}

	frames := fe.engine.WebMatchWithEngines(scanBytes, "fingers", "wappalyzer", "fingerprinthub", "ehole", "goby")

	tagSet := make(map[string]bool)
	for _, frame := range frames {
		tagSet[frame.Name] = true
		for _, tag := range frame.Tags {
			tagSet[tag] = true
		}
		if product == "" {
			product = frame.Name
		}
	}

	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags, product, vulns
}

// GrabBanner performs a single low-overhead banner grab (passive read, fallback to HTTP probe)
func (fe *FingerprintEngine) GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) []byte {
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := network.NewDialer(timeout)

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return buf[:n]
	}

	// 行业标准：通过外部化规则表或注册表进行协议回放 (Data-Driven Probing)
	// 此处模拟 Nmap/Nuclei 的探针外部化设计，将探针与网络执行逻辑解耦
	probePayload := getActiveProbePayload(port)
	if len(probePayload) == 0 {
		probePayload = []byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")
	}

	_, _ = conn.Write(probePayload)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	n, err = conn.Read(buf)
	if err == nil && n > 0 {
		return buf[:n]
	}

	return nil
}

// 模拟外部探针配置表 (在完整框架中应由 YAML/JSON 加载，如 Nuclei Templates 或 nmap-service-probes)
var activeProbeRegistry = map[int][]byte{
	135: {
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x40, 0xb8, 0x10, 0xe1, 0x9e, 0xbe, 0x11, 0xbf, 0xbf, 0x0e, 0x00, 0x00, 0x5b, 0x56, 0x50, 0x55,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
		0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	},
	445: []byte("\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"),
}

func getActiveProbePayload(port int) []byte {
	return activeProbeRegistry[port]
}

// IdentifyService captures banner in <300ms and executes zero-latency in-memory socket matching via fingers
func (fe *FingerprintEngine) IdentifyService(ctx context.Context, host string, port int, transport string) (protocol, product string, tags []string, confidence model.Confidence) {
	if transport == "tcp" {
		banner := fe.GrabBanner(ctx, host, port, 300*time.Millisecond)
		if len(banner) > 0 {
			if bytes.HasPrefix(banner, []byte("HTTP/")) {
				return "http", "", []string{"http"}, model.ConfidenceFirm
			}

			// Binary protocol exact signatures
			if len(banner) >= 8 && (bytes.Contains(banner[:8], []byte("SMB")) || bytes.Contains(banner[:8], []byte("\xffSMB")) || bytes.Contains(banner[:8], []byte("\xfeSMB"))) {
				return "microsoft-ds", "Microsoft Windows SMB", []string{"smb", "microsoft-ds"}, model.ConfidenceCertain
			}
			if len(banner) >= 3 && banner[0] == 0x05 && banner[1] == 0x00 && banner[2] == 0x0c {
				return "msrpc", "Microsoft Windows RPC", []string{"msrpc", "rpc"}, model.ConfidenceCertain
			}

			// In-memory socket matching via fingers engine without network overhead
			if fe.engine != nil {
				if feEngine, ok := fe.engine.GetEngine("fingers").(*rawfingers.FingersEngine); ok && feEngine != nil {
					portStr := strconv.Itoa(port)
					frame, _ := feEngine.SocketMatch(banner, portStr, 0, nil, nil)
					if frame != nil {
						proto := frame.Name
						return proto, proto, []string{proto}, model.ConfidenceCertain
					}
				}
			}
		}

		// Fallback for known quiet Windows internal service ports
		switch port {
		case 135:
			return "msrpc", "Microsoft Windows RPC", []string{"msrpc"}, model.ConfidenceTentative
		case 445:
			return "microsoft-ds", "Microsoft Windows SMB", []string{"smb", "microsoft-ds"}, model.ConfidenceTentative
		case 5040:
			return "cdp-usersvc", "Connected Devices Platform User Service", []string{"windows-cdp"}, model.ConfidenceTentative
		case 7680:
			return "p2p-wudo", "Windows Update Delivery Optimization", []string{"wudo"}, model.ConfidenceTentative
		}
	}

	return "unknown", "", nil, model.ConfidenceTentative
}

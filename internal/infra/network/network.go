package network

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

const (
	DefaultTimeout = 10 * time.Second
	UserAgent      = "DAST-Scanner/1.0"
)

type userAgentTransport struct {
	rt http.RoundTripper
}

func (u *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	return u.rt.RoundTrip(req)
}

// 构建扫描器的 HTTP 客户端
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100, 
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 是否验证证书签名
		},
	}

	return &http.Client{
		Transport: &userAgentTransport{rt: transport},
		Timeout:   timeout,
	}
}

// 统一的 TCP 拨号器
func NewDialer(timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &net.Dialer{
		Timeout: timeout,
	}
}

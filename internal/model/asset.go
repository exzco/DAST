package model

import (
	"fmt"
	"strings"
	"time"
)

type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	SubjectCN   string    `json:"subject_cn"`
	DNSNames    []string  `json:"dns_names"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsExpired   bool      `json:"is_expired"`
	ALPN        []string  `json:"alpn,omitempty"`
}

type Service struct {
	ID         string     `json:"id"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Transport  string     `json:"transport"` // tcp/udp
	Protocol   string     `json:"protocol"`  // http, https, ssh, mysql, etc.
	Product    string     `json:"product,omitempty"`
	Version    string     `json:"version,omitempty"`
	TLS        *TLSInfo   `json:"tls,omitempty"`
	Confidence Confidence `json:"confidence"`
	ObservedAt time.Time  `json:"observed_at"`
}

type Endpoint struct {
	ID           string    `json:"id"`
	ServiceID    string    `json:"service_id"`
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	Source       string    `json:"source"` // seed, dynamic_extract, openapi, robots
	CanonicalKey string    `json:"canonical_key"`
	ObservedAt   time.Time `json:"observed_at"`
}

func BuildEndpointCanonicalKey(method, rawURL string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	return fmt.Sprintf("%s %s", m, strings.TrimSpace(rawURL))
}

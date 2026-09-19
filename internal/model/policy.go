package model

import "time"

type CheckType string

const (
	CheckTypeProbe   CheckType = "PROBE"   // 指纹探测
	CheckTypeExploit CheckType = "EXPLOIT" // 漏洞利用 POC
)



type ScopeRule struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // CIDR, IP, DOMAIN, WILDCARD
	Pattern string `json:"pattern"`
	IsDeny  bool   `json:"is_deny"`
}

type RateLimitPolicy struct {
	MaxRPS            int `json:"max_rps"`
	MaxConcurrentHost int `json:"max_concurrent_host"`
	MaxConcurrentScan int `json:"max_concurrent_scan"`
}

type BudgetPolicy struct {
	MaxDurationMinutes int   `json:"max_duration_minutes"`
	MaxRequestsTotal   int64 `json:"max_requests_total"`
	MaxCrawlDepth      int   `json:"max_crawl_depth"`
	MaxEndpoints       int   `json:"max_endpoints"`
	MaxResponseBytes   int64 `json:"max_response_bytes"`
}

type PortScanPolicy struct {
	Profile     string `json:"profile"` // top100, top1000, full
	CustomPorts string `json:"custom_ports,omitempty"`
	TimeoutSec  int    `json:"timeout_sec"`
	RatePackets int    `json:"rate_packets"`
}

type Policy struct {
	ID        string          `json:"id"`
	Name       string          `json:"name"`
	ScopeRules []ScopeRule     `json:"scope_rules"`
	RateLimit  RateLimitPolicy `json:"rate_limit"`
	Budget    BudgetPolicy    `json:"budget"`
	PortScan  PortScanPolicy  `json:"port_scan"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func DefaultPolicy() *Policy {
	now := NowUTC()
	return &Policy{
		ID:        NewUUID(),
		Name:       "Default Basic Policy",
		ScopeRules: []ScopeRule{},
		RateLimit:  RateLimitPolicy{
			MaxRPS:            50,
			MaxConcurrentHost: 5,
			MaxConcurrentScan: 20,
		},
		Budget: BudgetPolicy{
			MaxDurationMinutes: 60,
			MaxRequestsTotal:   10000,
			MaxCrawlDepth:      3,
			MaxEndpoints:       500,
			MaxResponseBytes:   1024 * 1024 * 5, 
		},
		PortScan: PortScanPolicy{
			Profile:     "top1000",
			CustomPorts: "",
			TimeoutSec:  5,
			RatePackets: 1000,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

package model

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

type PortStatus string

const (
	PortStatusOpen     PortStatus = "OPEN"
	PortStatusClosed   PortStatus = "CLOSED"
	PortStatusFiltered PortStatus = "FILTERED"
	PortStatusTimeout  PortStatus = "TIMEOUT"
	PortStatusError    PortStatus = "ERROR"
)

type FactKind string

const (
	FactKindPortState   FactKind = "PORT_STATE"
	FactKindServiceInfo FactKind = "SERVICE_INFO"
	FactKindHeaderToken FactKind = "HEADER_TOKEN"
	FactKindBodyMatch   FactKind = "BODY_MATCH"
	FactKindTLSSubject  FactKind = "TLS_SUBJECT"
)

type Fact struct {
	ID          string     `json:"id"`
	ScanRunID   string     `json:"scan_run_id"`
	AssetKey    string     `json:"asset_key"`
	EndpointKey string     `json:"endpoint_key,omitempty"`
	Subject     string     `json:"subject"`
	Kind        FactKind   `json:"kind"`
	Value       string     `json:"value"`
	Version     string     `json:"version,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Source      string     `json:"source"`
	ObservedAt  time.Time  `json:"observed_at"`
	TTLSeconds  int64      `json:"ttl_seconds,omitempty"`
}

type PortObservation struct {
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Transport   string     `json:"transport"` // tcp/udp
	Status      PortStatus `json:"status"`    // OPEN, CLOSED, FILTERED
	DurationMs  int64      `json:"duration_ms"`
	ProbeSource string     `json:"probe_source"` // native, nmap
	ObservedAt  time.Time  `json:"observed_at"`
}

type FindingState string

const (
	FindingStateNew         FindingState = "NEW"
	FindingStateSuspected   FindingState = "SUSPECTED"
	FindingStateConfirmed   FindingState = "CONFIRMED"
	FindingStateFixed       FindingState = "FIXED"
	FindingStateFalsePos    FindingState = "FALSE_POSITIVE"
	FindingStateIgnored     FindingState = "IGNORED"
)

type Finding struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	ScanRunID    string       `json:"scan_run_id"`
	StableKey    string       `json:"stable_key"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     Severity     `json:"severity"`
	Confidence   Confidence   `json:"confidence"`
	State        FindingState `json:"state"`
	CheckID      string       `json:"check_id"`
	MatchedAt    string       `json:"matched_at"`
	Parameter    string       `json:"parameter,omitempty"`
	CVE          []string     `json:"cve,omitempty"`
	CWE          []string     `json:"cwe,omitempty"`
	CVSSScore    float64      `json:"cvss_score,omitempty"`
	Remediation  string       `json:"remediation,omitempty"`
	EvidenceRefs []string     `json:"evidence_refs"`
	Verified     bool         `json:"verified"`
	FirstSeen    time.Time    `json:"first_seen"`
	LastSeen     time.Time    `json:"last_seen"`
}

// 生成相应的 hash key 对每个资产
func GenerateStableFindingKey(tenantID, canonicalAsset, canonicalEndpoint, checkID, parameter, variant string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		strings.ToLower(tenantID),
		strings.ToLower(canonicalAsset),
		strings.ToLower(canonicalEndpoint),
		strings.ToLower(checkID),
		strings.ToLower(parameter),
		strings.ToLower(variant),
	)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

func HashContent(content []byte) string {
	h := sha256.Sum256(content)
	return fmt.Sprintf("%x", h)
}

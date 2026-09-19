package model

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type TargetKind string

const (
	TargetKindIP       TargetKind = "IP"
	TargetKindCIDR     TargetKind = "CIDR"
	TargetKindDomain   TargetKind = "DOMAIN"
	TargetKindURL      TargetKind = "URL"
	TargetKindHostPort TargetKind = "HOST_PORT"
)

type NormalizedTarget struct {
	RawInput        string     `json:"raw_input"`
	Host            string     `json:"host"`
	Port            int        `json:"port,omitempty"`
	Scheme          string     `json:"scheme,omitempty"`
	Kind            TargetKind `json:"kind"`
	AssetKey        string     `json:"asset_key"`
	CanonicalTarget string     `json:"canonical_target"`
	IsValid         bool       `json:"is_valid"`
	ValidationError string     `json:"validation_error,omitempty"`
}

type ScopeVerdict string

const (
	ScopeVerdictAllowed ScopeVerdict = "ALLOWED"
	ScopeVerdictDenied  ScopeVerdict = "DENIED"
	ScopeVerdictInvalid ScopeVerdict = "INVALID"
)

func ParseAndNormalizeTarget(raw string) *NormalizedTarget {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return &NormalizedTarget{
			RawInput:        raw,
			IsValid:         false,
			ValidationError: "empty target string",
		}
	}

	res := &NormalizedTarget{
		RawInput: trimmed,
		IsValid:  true,
	}

	// 1. URL
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.Hostname() == "" {
			res.IsValid = false
			res.ValidationError = fmt.Sprintf("invalid url format: %v", err)
			return res
		}
		res.Kind = TargetKindURL
		res.Scheme = strings.ToLower(u.Scheme)
		res.Host = strings.ToLower(u.Hostname())
		res.AssetKey = res.Host

		if u.Port() != "" {
			p, err := strconv.Atoi(u.Port())
			if err != nil || p < 1 || p > 65535 {
				res.IsValid = false
				res.ValidationError = fmt.Sprintf("invalid port in url: %s", u.Port())
				return res
			}
			res.Port = p
		} else {
			if res.Scheme == "https" {
				res.Port = 443
			} else if res.Scheme == "http" {
				res.Port = 80
			}
		}
		res.CanonicalTarget = fmt.Sprintf("%s:%d", res.Host, res.Port)
		return res
	}

	// 2. CIDR
	if strings.Contains(trimmed, "/") {
		_, _, err := net.ParseCIDR(trimmed)
		if err != nil {
			res.IsValid = false
			res.ValidationError = fmt.Sprintf("invalid cidr format: %v", err)
			return res
		}
		res.Kind = TargetKindCIDR
		res.Host = trimmed
		res.AssetKey = trimmed
		res.CanonicalTarget = trimmed
		return res
	}

	// 3. Host:Port
	if strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "]:") && !strings.HasPrefix(trimmed, "[") {
		host, portStr, err := net.SplitHostPort(trimmed)
		if err == nil {
			p, pErr := strconv.Atoi(portStr)
			if pErr == nil && p >= 1 && p <= 65535 {
				res.Kind = TargetKindHostPort
				res.Host = strings.ToLower(host)
				res.Port = p
				res.AssetKey = res.Host
				res.CanonicalTarget = fmt.Sprintf("%s:%d", res.Host, res.Port)
				return res
			}
		}
	}

	// 4. IP
	if ip := net.ParseIP(trimmed); ip != nil {
		res.Kind = TargetKindIP
		res.Host = trimmed
		res.AssetKey = trimmed
		res.CanonicalTarget = trimmed
		return res
	}

	// 5. Domain
	res.Kind = TargetKindDomain
	res.Host = strings.ToLower(trimmed)
	res.AssetKey = res.Host
	res.CanonicalTarget = res.Host
	return res
}

func ExpandTargets(rawList []string) []*NormalizedTarget {
	var result []*NormalizedTarget
	seen := make(map[string]bool)

	for _, raw := range rawList {
		norm := ParseAndNormalizeTarget(raw)
		if !norm.IsValid {
			result = append(result, norm)
			continue
		}

		if norm.Kind == TargetKindCIDR {
			_, ipNet, err := net.ParseCIDR(norm.RawInput)
			if err == nil {
				for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
					ipStr := ip.String()
					if !seen[ipStr] {
						seen[ipStr] = true
						subNorm := ParseAndNormalizeTarget(ipStr)
						result = append(result, subNorm)
					}
				}
				continue
			}
		}

		key := norm.CanonicalTarget
		if !seen[key] {
			seen[key] = true
			result = append(result, norm)
		}
	}
	return result
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
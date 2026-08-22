package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"distributed-scanner/internal/engine"
	"distributed-scanner/internal/model"
)

type ReportExporter struct{}

func NewReportExporter() *ReportExporter {
	return &ReportExporter{}
}

func (e *ReportExporter) ExportJSON(res *engine.ScanResult, outPath string) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	dir := filepath.Dir(outPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(outPath, data, 0644)
}

func (e *ReportExporter) ExportMarkdown(res *engine.ScanResult, outPath string) error {
	var sb strings.Builder

	sb.WriteString("# 🛡️ DAST 漏洞扫描报告 (Executive Scan Report)\n\n")
	sb.WriteString(fmt.Sprintf("- **任务 ID**: `%s`\n", res.ScanRunID))
	sb.WriteString(fmt.Sprintf("- **开始时间**: `%s`\n", res.StartedAt.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("- **完成时间**: `%s`\n", res.CompletedAt.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("- **总耗时**: `%d ms`\n\n", res.DurationMs))

	sb.WriteString("## 1. 扫描概要 (Executive Summary)\n\n")
	sb.WriteString("| 指标项 | 统计数量 |\n")
	sb.WriteString("|---|---|\n")
	sb.WriteString(fmt.Sprintf("| 扫描目标总数 | %d |\n", res.Stats.TotalTargets))
	sb.WriteString(fmt.Sprintf("| 发现开放端口 | %d |\n", res.Stats.OpenPorts))
	sb.WriteString(fmt.Sprintf("| 识别网络服务 | %d |\n", res.Stats.ServicesFound))
	sb.WriteString(fmt.Sprintf("| 发现 Web 端点 | %d |\n", res.Stats.EndpointsFound))
	sb.WriteString(fmt.Sprintf("| 确证漏洞总数 | %d |\n\n", len(res.Findings)))

	sb.WriteString("## 2. 发现的漏洞清单 (Findings)\n\n")
	if len(res.Findings) == 0 {
		sb.WriteString("✨ **未发现任何已知风险漏洞**。\n\n")
	} else {
		sb.WriteString("| 严重度 | 漏洞名称 | 规则 ID | 命中目标 | 置信度 |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, f := range res.Findings {
			badge := severityBadge(f.Severity)
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | `%s` | `%.2f` |\n", badge, f.Title, f.CheckID, f.MatchedAt, float64(f.Confidence)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 3. 资产与网络服务详情 (Services Discovered)\n\n")
	if len(res.Services) == 0 {
		sb.WriteString("未发现开放服务。\n\n")
	} else {
		sb.WriteString("| 目标主机 | 端口 | 传输层 | 识别协议 | 产品组件 |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, s := range res.Services {
			prod := s.Product
			if prod == "" {
				prod = "-"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%d` | `%s` | `%s` | `%s` |\n", s.Host, s.Port, s.Transport, s.Protocol, prod))
		}
		sb.WriteString("\n")
	}

	dir := filepath.Dir(outPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(outPath, []byte(sb.String()), 0644)
}

func severityBadge(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "🔴 严重 (CRITICAL)"
	case model.SeverityHigh:
		return "🟠 高危 (HIGH)"
	case model.SeverityMedium:
		return "🟡 中危 (MEDIUM)"
	case model.SeverityLow:
		return "🔵 低危 (LOW)"
	default:
		return "⚪ 提示 (INFO)"
	}
}

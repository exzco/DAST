// Package engine provides core scanning and POC execution logic.
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"distributed-scanner/internal/model"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RuleIndex 倒排索引：按协议/产品/标签快速选取待执行漏洞检查规则
type RuleIndex struct {
	mu         sync.RWMutex
	specs      []model.CheckSpec
	byProtocol map[string][]int
	byProduct  map[string][]int
	byTag      map[string][]int
}

// NewRuleIndex 构建空索引并装载内置 POC 规则目录
func NewRuleIndex() *RuleIndex {
	idx := &RuleIndex{
		byProtocol: make(map[string][]int),
		byProduct:  make(map[string][]int),
		byTag:      make(map[string][]int),
	}
	for _, spec := range DefaultCheckCatalog() {
		idx.AddSpec(spec)
	}
	return idx
}

// AddSpec 注册一条检查规则到倒排索引
func (idx *RuleIndex) AddSpec(spec model.CheckSpec) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idxPos := len(idx.specs)
	idx.specs = append(idx.specs, spec)

	for _, proto := range spec.Prerequisites.Protocols {
		p := strings.ToLower(proto)
		idx.byProtocol[p] = append(idx.byProtocol[p], idxPos)
	}

	for _, prod := range spec.Prerequisites.Products {
		pr := strings.ToLower(prod)
		idx.byProduct[pr] = append(idx.byProduct[pr], idxPos)
	}

	for _, tag := range spec.Tags {
		t := strings.ToLower(tag)
		idx.byTag[t] = append(idx.byTag[t], idxPos)
	}
}

// SelectChecks 按资产事实(产品/技术栈/标签)匹配候选漏洞检查规则
func (idx *RuleIndex) SelectChecks(facts []model.Fact, pol *model.Policy) []model.CheckSpec {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	matchedIndices := make(map[int]bool)

	for _, f := range facts {
		subject := strings.ToLower(strings.TrimSpace(f.Subject))
		if positions, found := idx.byProduct[subject]; found {
			for _, pos := range positions {
				matchedIndices[pos] = true
			}
		}
		if positions, found := idx.byTag[subject]; found {
			for _, pos := range positions {
				matchedIndices[pos] = true
			}
		}
		if positions, found := idx.byProtocol[subject]; found {
			for _, pos := range positions {
				matchedIndices[pos] = true
			}
		}
	}

	var selected []model.CheckSpec
	for pos := range matchedIndices {
		spec := idx.specs[pos]
		if !passPolicy(spec, pol) {
			continue
		}
		selected = append(selected, spec)
	}
	return selected
}

// SelectByProtocol 按协议前置条件选取规则（http/https 服务的通用 Web 漏洞规则）
func (idx *RuleIndex) SelectByProtocol(protocol string, pol *model.Policy) []model.CheckSpec {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var selected []model.CheckSpec
	for _, pos := range idx.byProtocol[strings.ToLower(protocol)] {
		spec := idx.specs[pos]
		if !passPolicy(spec, pol) {
			continue
		}
		selected = append(selected, spec)
	}
	return selected
}

// passPolicy 规则策略过滤：侵入级别与拒绝标签
func passPolicy(spec model.CheckSpec, pol *model.Policy) bool {
	if pol == nil {
		return true
	}
	if spec.IntrusiveLevel == model.IntrusiveLevelIntrusive && pol.IntrusiveLevel != model.IntrusiveLevelIntrusive {
		return false
	}
	for _, dt := range pol.DeniedTags {
		for _, st := range spec.Tags {
			if strings.EqualFold(dt, st) {
				return false
			}
		}
	}
	return true
}

func DefaultCheckCatalog() []model.CheckSpec {
	spec := func(id, name string, tags, products, protocols []string) model.CheckSpec {
		return model.CheckSpec{
			ID:             id,
			Name:           name,
			Kind:           model.PluginKindNuclei,
			Severity:       model.SeverityHigh,
			IntrusiveLevel: model.IntrusiveLevelSafe,
			Prerequisites:  model.Prerequisite{Protocols: protocols, Products: products},
			Tags:           tags,
			TimeoutSec:     60,
			Version:        "1.0",
		}
	}

	web := []string{"http", "https"}
	return []model.CheckSpec{
		spec("nuclei-sqli", "SQL 注入检测", []string{"sqli", "sql-injection"}, nil, web),
		spec("nuclei-xss", "跨站脚本 XSS 检测", []string{"xss"}, nil, web),
		spec("nuclei-ssrf", "服务端请求伪造 SSRF 检测", []string{"ssrf"}, nil, web),
		spec("nuclei-lfi", "本地文件包含 LFI 检测", []string{"lfi"}, nil, web),
		spec("nuclei-rce", "命令注入 / 远程代码执行检测", []string{"rce", "command-injection"}, nil, web),
		spec("nuclei-exposed-panels", "暴露管理面板检测", []string{"exposed-panels"}, nil, web),
		spec("nuclei-default-logins", "默认口令弱凭据检测", []string{"default-logins"}, nil, web),
		spec("nuclei-misconfig", "常见错误配置检测", []string{"misconfiguration"}, nil, web),
		spec("nuclei-ssti", "模板注入 SSTI 检测", []string{"ssti"}, nil, web),
		spec("nuclei-xxe", "XML 外部实体 XXE 检测", []string{"xxe"}, nil, web),
		spec("nuclei-crlf", "CRLF 注入检测", []string{"crlf"}, nil, web),
		spec("nuclei-wordpress", "WordPress 漏洞检测", []string{"wordpress"}, []string{"wordpress"}, web),
		spec("nuclei-joomla", "Joomla 漏洞检测", []string{"joomla"}, []string{"joomla"}, web),
		spec("nuclei-drupal", "Drupal 漏洞检测", []string{"drupal"}, []string{"drupal"}, web),
		spec("nuclei-phpmyadmin", "phpMyAdmin 漏洞检测", []string{"phpmyadmin"}, []string{"phpmyadmin"}, web),
		spec("nuclei-jenkins", "Jenkins 漏洞检测", []string{"jenkins"}, []string{"jenkins"}, web),
		spec("nuclei-tomcat", "Tomcat 漏洞检测", []string{"tomcat"}, []string{"tomcat"}, web),
		spec("nuclei-nginx", "Nginx 漏洞检测", []string{"nginx"}, []string{"nginx"}, web),
		spec("nuclei-apache", "Apache 漏洞检测", []string{"apache"}, []string{"apache"}, web),
		spec("nuclei-php", "PHP 应用漏洞检测", []string{"php"}, []string{"php"}, web),
		spec("nuclei-nodejs", "Node.js 应用漏洞检测", []string{"nodejs", "node.js"}, []string{"node.js", "nodejs", "express"}, web),
	}
}

type NucleiCheckExecutor struct {
	pocDir string
}

func NewNucleiCheckExecutor(pocDir string) *NucleiCheckExecutor {
	return &NucleiCheckExecutor{pocDir: pocDir}
}
func (e *NucleiCheckExecutor) ExecuteChecks(ctx context.Context, specs []model.CheckSpec, targetCtx CheckContext) ([]model.Finding, error) {
	tagSet := make(map[string]struct{})
	for _, spec := range specs {
		for _, t := range spec.Tags {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" {
				tagSet[t] = struct{}{}
			}
		}
	}
	if len(tagSet) == 0 {
		return nil, nil
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	filters := nuclei.TemplateFilters{Tags: tags}
	if targetCtx.Policy != nil && len(targetCtx.Policy.DeniedTags) > 0 {
		filters.ExcludeTags = targetCtx.Policy.DeniedTags
	}

	opts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.WithSandboxOptions(true, false),
		nuclei.WithTemplateFilters(filters),
	}
	if e.pocDir != "" {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{e.pocDir}}))
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create nuclei engine: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets([]string{targetCtx.TargetURL}, false)

	var findings []model.Finding
	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		// 过滤非命中事件：请求错误 / 目标无响应导致的模板跳过通知（error 事件）不是漏洞，
		if event.Error != "" || !event.MatcherStatus {
			return
		}

		evidenceHash := model.HashContent([]byte(event.Response))
		f := model.Finding{
			ID:           model.NewUUID(),
			ScanRunID:    targetCtx.ScanRunID,
			Title:        event.Info.Name,
			Description:  event.Info.Description,
			Severity:     mapNucleiSeverity(event.Info.SeverityHolder.Severity.String()),
			Confidence:   model.ConfidenceCertain,
			State:        model.FindingStateConfirmed,
			CheckID:      event.TemplateID,
			MatchedAt:    event.Matched,
			EvidenceRefs: []string{evidenceHash},
			Verified:     true,
			FirstSeen:    time.Now().UTC(),
			LastSeen:     time.Now().UTC(),
		}
		if targetCtx.Policy != nil {
			f.TenantID = targetCtx.Policy.TenantID
			f.StableKey = model.GenerateStableFindingKey(
				targetCtx.Policy.TenantID,
				targetCtx.ServiceHost,
				targetCtx.TargetURL,
				event.TemplateID,
				"",
				"",
			)
		}
		findings = append(findings, f)
	})
	if err != nil {
		return nil, fmt.Errorf("execute nuclei checks: %w", err)
	}
	return findings, nil
}

func mapNucleiSeverity(sev string) model.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

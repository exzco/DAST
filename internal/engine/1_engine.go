package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"distributed-scanner/internal/model"
)

type ProbeRequest struct {
	Host       string               `json:"host"`
	Port       int                  `json:"port,omitempty"`
	Transport  string               `json:"transport"`
	PortRange  string               `json:"port_range,omitempty"`
	ScanPolicy model.PortScanPolicy `json:"scan_policy"`
}

type CheckContext struct {
	ScanRunID   string        `json:"scan_run_id"`
	TargetURL   string        `json:"target_url"`
	ServiceHost string        `json:"service_host"`
	ServicePort int           `json:"service_port"`
	Protocol    string        `json:"protocol"`
	Facts       []model.Fact  `json:"facts"`
	Policy      *model.Policy `json:"policy"`
}

type ProbeAdapter interface {
	ScanPorts(ctx context.Context, req ProbeRequest) ([]model.PortObservation, error)
}

type CheckExecutor interface {
	ExecuteChecks(ctx context.Context, specs []model.CheckSpec, targetCtx CheckContext) ([]model.Finding, error)
}

type ProgressEvent struct {
	Step        int           `json:"step"`
	TotalSteps  int           `json:"total_steps"`
	StageName   string        `json:"stage_name"`
	Message     string        `json:"message"`
	Duration    time.Duration `json:"duration"`
	Target      string        `json:"target,omitempty"`
	OpenPorts   []int         `json:"open_ports,omitempty"`
	FactsCount  int           `json:"facts_count,omitempty"`
	FindingName string        `json:"finding_name,omitempty"`
	Severity    string        `json:"severity,omitempty"`
}

type ProgressCallback func(event ProgressEvent)

type ScanOptions struct {
	Targets      []string         `json:"targets"`
	Profile      string           `json:"profile"` // fast, balanced, deep
	PortOverride string           `json:"port_override,omitempty"`
	Policy       *model.Policy    `json:"policy,omitempty"`
	PocDir       string           `json:"poc_dir,omitempty"`
	OnProgress   ProgressCallback `json:"-"`
}

type ScanResult struct {
	ScanRunID    string                   `json:"scan_run_id"`
	StartedAt    time.Time                `json:"started_at"`
	CompletedAt  time.Time                `json:"completed_at"`
	DurationMs   int64                    `json:"duration_ms"`
	Targets      []model.NormalizedTarget `json:"targets"`
	Observations []model.PortObservation  `json:"observations"`
	Services     []model.Service          `json:"services"`
	Endpoints    []model.Endpoint         `json:"endpoints"`
	Facts        []model.Fact             `json:"facts"`
	Findings     []model.Finding          `json:"findings"`
	Stats        model.ScanRunStats       `json:"stats"`
}


type Runner struct {
	probeAdapter  ProbeAdapter
	checkExecutor CheckExecutor
	httpClient    *HTTPClient
	tlsAnalyzer   *TLSAnalyzer
	ruleIndex     *RuleIndex
	fpEngine      *FingerprintEngine
	nmapScanner   *NmapServiceScanner
}

func NewRunner(probe ProbeAdapter, check CheckExecutor, pocDir string) *Runner {
	idx := NewRuleIndex()
	httpClient := NewHTTPClient(10 * time.Second)
	return &Runner{
		probeAdapter:  probe,
		checkExecutor: check,
		httpClient:    httpClient,
		tlsAnalyzer:   NewTLSAnalyzer(5 * time.Second),
		ruleIndex:     idx,
		fpEngine:      NewFingerprintEngine("data/fingerprints.json"),
		nmapScanner:   NewNmapServiceScanner(),
	}
}

// 总函数 ，流水线运行 ，目标解析，端口探活，服务识别，poc验证，去重统计。
func (r *Runner) Run(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	start := time.Now()
	scanRunID := model.NewUUID()

	pol := opts.Policy
	if pol == nil {
		pol = model.DefaultPolicy("local-user")
	}

	rateLimiter := NewRateLimiter(pol.RateLimit.MaxRPS, pol.RateLimit.MaxConcurrentScan)
	budgetTracker := NewBudgetTracker(pol.Budget)
	aggregator := NewAggregator()

	var normalizedTargets []model.NormalizedTarget
	var allFacts []model.Fact
	var allServices []model.Service
	var allEndpoints []model.Endpoint

	emit := func(step int, stageName, message string, extra ...func(*ProgressEvent)) {
		if opts.OnProgress != nil {
			ev := ProgressEvent{
				Step:       step,
				TotalSteps: 5,
				StageName:  stageName,
				Message:    message,
				Duration:   time.Since(start),
			}
			for _, fn := range extra {
				fn(&ev)
			}
			opts.OnProgress(ev)
		}
	}

    // 1. 目标解析
	stage1Start := time.Now()
	expanded := model.ExpandTargets(opts.Targets)

	for _, tgt := range expanded {
		if !tgt.IsValid {
			emit(1, "目标解析", fmt.Sprintf("⚠️ 目标格式无效: %s (错误: %s)", tgt.RawInput, tgt.ValidationError))
			continue
		}

		if tgt.Kind == model.TargetKindDomain {
			ips, err := net.LookupIP(tgt.Host)
			if err == nil && len(ips) > 0 {
				emit(1, "目标解析", fmt.Sprintf("🌐 域名解析成功: %s -> %s", tgt.Host, ips[0].String()))
			}
		}

		normalizedTargets = append(normalizedTargets, *tgt)
		emit(1, "目标解析", fmt.Sprintf("🎯 目标规范化完成: %s -> %s (类型: %s, 资产Key: %s)", tgt.RawInput, tgt.CanonicalTarget, tgt.Kind, tgt.AssetKey), func(e *ProgressEvent) {
			e.Target = tgt.CanonicalTarget
		})
	}
	emit(1, "目标解析", fmt.Sprintf("✅ 阶段 1/5 完成: 共展开并就绪 %d 个目标资产 (耗时: %s)", len(normalizedTargets), time.Since(stage1Start)))

	if len(normalizedTargets) == 0 {
		return nil, fmt.Errorf("no valid targets to scan")
	}

    // 2. 端口探活
	stage2Start := time.Now()
	for _, tgt := range normalizedTargets {
		_ = rateLimiter.Wait(ctx, tgt.Host)
		_ = budgetTracker.CheckAndRecordRequest()

		portRange := opts.PortOverride
		if portRange == "" && tgt.Port > 0 {
			portRange = fmt.Sprintf("%d", tgt.Port)
		}
		if portRange == "" {
			portRange = pol.PortScan.Profile
		}

		req := ProbeRequest{
			Host:       tgt.Host,
			Port:       tgt.Port,
			Transport:  "tcp",
			PortRange:  portRange,
			ScanPolicy: pol.PortScan,
		}

		emit(2, "端口存活", fmt.Sprintf("🔍 正在探测端口: %s (范围: %s)...", tgt.Host, portRange))
		observations, err := r.probeAdapter.ScanPorts(ctx, req)
		if err != nil {
			emit(2, "端口存活", fmt.Sprintf("❌ 端口扫描异常 %s: %v", tgt.Host, err))
			continue
		}

		var openPortList []int
		for _, obs := range observations {
			aggregator.IngestObservation(obs)
			if obs.Status == model.PortStatusOpen {
				openPortList = append(openPortList, obs.Port)
			}
		}

		emit(2, "端口存活", fmt.Sprintf("🔓 目标 %s 发现 %d 个开放端口: %v", tgt.Host, len(openPortList), openPortList), func(e *ProgressEvent) {
			e.Target = tgt.Host
			e.OpenPorts = openPortList
		})
	}
	emit(2, "端口存活", fmt.Sprintf("✅ 阶段 2/5 完成: 累计发现开放端口 %d 个 (耗时: %s)", aggregator.Stats().OpenPorts, time.Since(stage2Start)))
    
	// 3. 服务识别
	stage3Start := time.Now()
	openObs := aggregator.GetUniqueObservations()

	// 收集开放端口按主机分组，用于集中进行 Nmap binary 探测
	hostOpenPorts := make(map[string][]int)
	for _, obs := range openObs {
		if obs.Status == model.PortStatusOpen {
			hostOpenPorts[obs.Host] = append(hostOpenPorts[obs.Host], obs.Port)
		}
	}

	// 针对各主机的开放端口，先尝试 Nmap 服务探测
	nmapServicesByHost := make(map[string]map[int]model.Service)
	for host, ports := range hostOpenPorts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		emit(3, "服务识别", fmt.Sprintf("🔍 正在调用 Nmap 探测 Binary 服务版本: %s (端口: %v)...", host, ports))
		nmapServicesByHost[host] = r.nmapScanner.DetectServices(ctx, host, ports)
	}

	for _, obs := range openObs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if obs.Status != model.PortStatusOpen {
			continue
		}

		_ = rateLimiter.Wait(ctx, obs.Host)
		emit(3, "服务识别", fmt.Sprintf("🏷️ 正在分析协议与服务: %s:%d...", obs.Host, obs.Port))

		// 1. 优先使用 Nmap 针对 Bin 程序的探测结果
		var svc model.Service
		var tags []string
		if nmapSvcMap, ok := nmapServicesByHost[obs.Host]; ok {
			if nmapSvc, found := nmapSvcMap[obs.Port]; found && nmapSvc.Protocol != "" && nmapSvc.Protocol != "unknown" {
				svc = nmapSvc
				if svc.Product != "" {
					tags = append(tags, svc.Product)
				}
				if svc.Protocol != "" {
					tags = append(tags, svc.Protocol)
				}
			}
		}

		// 2. 若 Nmap 未探测到，则执行自研 Banner 探测
		if svc.Protocol == "" || svc.Protocol == "unknown" {
			proto, prod, fpTags, conf := r.fpEngine.IdentifyService(ctx, obs.Host, obs.Port, obs.Transport)
			svc = model.Service{
				ID:         model.NewUUID(),
				Host:       obs.Host,
				Port:       obs.Port,
				Transport:  obs.Transport,
				Protocol:   proto,
				Product:    prod,
				Confidence: conf,
				ObservedAt: time.Now().UTC(),
			}
			tags = fpTags
		}

		// 3. TLS 握手检测
		if obs.Port == 443 || obs.Port == 8443 || svc.Protocol == "https" {
			tlsInfo, err := r.tlsAnalyzer.Analyze(ctx, obs.Host, obs.Port)
			if err == nil && tlsInfo != nil {
				svc.Protocol = "https"
				svc.TLS = tlsInfo
				svc.Confidence = model.ConfidenceCertain
				emit(3, "服务识别", fmt.Sprintf("🔒 TLS 握手成功 %s:%d (版本: %s, 证书: %s)", obs.Host, obs.Port, tlsInfo.Version, tlsInfo.SubjectCN))
			}
		}

		if svc.Protocol != "http" && svc.Protocol != "https" {
			testURL := fmt.Sprintf("http://%s:%d/", svc.Host, svc.Port)
			if resp, err := r.httpClient.Do(ctx, "GET", testURL, nil, ""); err == nil && resp != nil {
				svc.Protocol = "http"
				svc.Confidence = model.ConfidenceFirm
			}
		}

		allServices = append(allServices, svc)

		// 记录 Banner/Nmap 提取数据
		for _, tag := range tags {
			allFacts = append(allFacts, model.Fact{
				ID:         model.NewUUID(),
				ScanRunID:  scanRunID,
				AssetKey:   obs.Host,
				Subject:    tag,
				Kind:       model.FactKindServiceInfo,
				Value:      svc.Product,
				Confidence: svc.Confidence,
				Source:     "service_probe",
				ObservedAt: time.Now().UTC(),
			})
		}
		if svc.Product != "" {
			allFacts = append(allFacts, model.Fact{
				ID:         model.NewUUID(),
				ScanRunID:  scanRunID,
				AssetKey:   obs.Host,
				Subject:    svc.Product,
				Kind:       model.FactKindServiceInfo,
				Value:      svc.Product,
				Confidence: svc.Confidence,
				Source:     "service_product",
				ObservedAt: time.Now().UTC(),
			})
		}

		// 4. Web 服务识别：Wappalyzer +  FingerprintEngine 自定义规则
		if svc.Protocol == "http" || svc.Protocol == "https" {
			baseURL := fmt.Sprintf("%s://%s:%d", svc.Protocol, svc.Host, svc.Port)
			resp, err := r.httpClient.Do(ctx, "GET", baseURL, nil, "")
			if err == nil && resp != nil {
				allEndpoints = append(allEndpoints, model.Endpoint{
					ID:           model.NewUUID(),
					ServiceID:    svc.ID,
					URL:          baseURL + "/",
					Method:       "GET",
					Path:         "/",
					Source:       "seed",
					CanonicalKey: model.BuildEndpointCanonicalKey("GET", baseURL+"/"),
					ObservedAt:   time.Now().UTC(),
				})

				webTags, webProd := r.fpEngine.DetectWebTechnologies(resp.RawHeader, resp.Headers, resp.Body)
				if webProd != "" {
					svc.Product = webProd
					svc.Confidence = model.ConfidenceCertain
				}
				for _, wt := range webTags {
					allFacts = append(allFacts, model.Fact{
						ID:         model.NewUUID(),
						ScanRunID:  scanRunID,
						AssetKey:   svc.Host,
						Subject:    wt,
						Kind:       model.FactKindServiceInfo,
						Value:      webProd,
						Confidence: model.ConfidenceCertain,
						Source:     "wappalyzer_fingerprint",
						ObservedAt: time.Now().UTC(),
					})
				}

				if serverHdr, ok := resp.Headers["Server"]; ok && serverHdr != "" {
					allFacts = append(allFacts, model.Fact{
						ID:         model.NewUUID(),
						ScanRunID:  scanRunID,
						AssetKey:   svc.Host,
						Subject:    extractProductFromHeader(serverHdr),
						Kind:       model.FactKindHeaderToken,
						Value:      serverHdr,
						Confidence: model.ConfidenceCertain,
						Source:     "header:Server",
						ObservedAt: time.Now().UTC(),
					})
				}

				extractedLinks := ExtractLinks(baseURL, resp.Body)
				for _, link := range extractedLinks {
					allEndpoints = append(allEndpoints, model.Endpoint{
						ID:           model.NewUUID(),
						ServiceID:    svc.ID,
						URL:          baseURL + link,
						Method:       "GET",
						Path:         link,
						Source:       "dynamic_extract",
						CanonicalKey: model.BuildEndpointCanonicalKey("GET", baseURL+link),
						ObservedAt:   time.Now().UTC(),
					})
				}
				if len(extractedLinks) > 0 {
					emit(3, "服务识别", fmt.Sprintf("🌐 从 HTML/JS 中提取出 %d 个动态端点与 API 路由", len(extractedLinks)))
				}
			}
		}
	}

	emit(3, "服务识别", fmt.Sprintf("🏷️ 识别提取到 %d 项服务与技术栈事实", len(allFacts)), func(e *ProgressEvent) {
		e.FactsCount = len(allFacts)
	})
	for _, f := range allFacts {
		if f.Subject != "" {
			emit(3, "服务识别", fmt.Sprintf("   - 资产事实: %s:%s (来源: %s)", f.Subject, f.Value, f.Source))
		}
	}
	emit(3, "服务识别", fmt.Sprintf("✅ 阶段 3/5 完成: 已识别服务 %d 个, 发现 Web 端点 %d 个 (耗时: %s)", len(allServices), len(allEndpoints), time.Since(stage3Start)))

	// 4. nuclei POC 验证
	stage4Start := time.Now()
	baseChecks := r.ruleIndex.SelectChecks(allFacts, pol)
	emit(4, "POC 验证", fmt.Sprintf("📋 倒排索引规则规划完成: 按资产事实匹配 %d 项漏洞检查", len(baseChecks)))

	// 仅对 web 服务使用 nuclei 
	for _, svc := range allServices {
		if svc.Protocol != "http" && svc.Protocol != "https" {
			continue
		}

		checks := baseChecks
		for _, spec := range r.ruleIndex.SelectByProtocol(svc.Protocol, pol) {
			duplicated := false
			for _, c := range checks {
				if c.ID == spec.ID {
					duplicated = true
					break
				}
			}
			if !duplicated {
				checks = append(checks, spec)
			}
		}
		if len(checks) == 0 {
			continue
		}

		targetURL := fmt.Sprintf("%s://%s:%d", svc.Protocol, svc.Host, svc.Port)
		targetCtx := CheckContext{
			ScanRunID:   scanRunID,
			TargetURL:   targetURL,
			ServiceHost: svc.Host,
			ServicePort: svc.Port,
			Protocol:    svc.Protocol,
			Facts:       allFacts,
			Policy:      pol,
		}

		emit(4, "POC 验证", fmt.Sprintf("🛡️ 正在对 %s 聚合执行 %d 项漏洞检查...", targetURL, len(checks)))
		findings, err := r.checkExecutor.ExecuteChecks(ctx, checks, targetCtx)
		if err != nil {
			emit(4, "POC 验证", fmt.Sprintf("⚠️ 检查执行告警 [%s]: %v", targetURL, err))
			continue
		}

		for _, f := range findings {
			aggregator.IngestFinding(f)
			emit(4, "POC 验证", fmt.Sprintf("🚨 发现并确证漏洞: [%s] %s (严重度: %s, 目标: %s)", f.CheckID, f.Title, f.Severity, f.MatchedAt), func(e *ProgressEvent) {
				e.FindingName = f.Title
				e.Severity = string(f.Severity)
			})
		}
	}
	emit(4, "POC 验证", fmt.Sprintf("✅ 阶段 4/5 完成: 累计确证漏洞 %d 个 (耗时: %s)", len(aggregator.GetUniqueFindings()), time.Since(stage4Start)))


	// 5. 去重报告输出
	stage5Start := time.Now()
	uniqueFindings := aggregator.GetUniqueFindings()
	finalStats := aggregator.Stats()
	finalStats.TotalTargets = len(normalizedTargets)
	finalStats.ScannedTargets = len(normalizedTargets)
	finalStats.ServicesFound = len(allServices)
	finalStats.EndpointsFound = len(allEndpoints)
	finalStats.FindingsCount = len(uniqueFindings)
	finalStats.DurationMs = time.Since(start).Milliseconds()

	emit(5, "去重报告输出", fmt.Sprintf("📊 正在执行资产维度去重与汇聚... 总耗时: %s", time.Since(start)))
	emit(5, "去重报告输出", fmt.Sprintf("✅ 阶段 5/5 完成 (耗时: %s)", time.Since(stage5Start)))

	return &ScanResult{
		ScanRunID:    scanRunID,
		StartedAt:    start,
		CompletedAt:  time.Now(),
		DurationMs:   time.Since(start).Milliseconds(),
		Targets:      normalizedTargets,
		Observations: aggregator.GetUniqueObservations(),
		Services:     allServices,
		Endpoints:    allEndpoints,
		Facts:        allFacts,
		Findings:     uniqueFindings,
		Stats:        finalStats,
	}, nil
}

func extractProductFromHeader(hdr string) string {
	lower := strings.ToLower(hdr)
	if strings.Contains(lower, "nginx") {
		return "nginx"
	}
	if strings.Contains(lower, "apache") {
		return "apache"
	}
	if strings.Contains(lower, "tomcat") {
		return "tomcat"
	}
	if strings.Contains(lower, "kibana") {
		return "kibana"
	}
	if strings.Contains(lower, "grafana") {
		return "grafana"
	}
	return strings.Split(lower, "/")[0]
}

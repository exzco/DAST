package main

import (
	"context"
	"distributed-scanner/internal/domain/poc"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"distributed-scanner/internal/app/api"
	"distributed-scanner/internal/config"
	"distributed-scanner/internal/infra/mq"
	"distributed-scanner/pkg/pipeline"
	"distributed-scanner/internal/domain/portscan"

	"distributed-scanner/internal/model"
	"distributed-scanner/internal/app/updater"

	"github.com/redis/go-redis/v9"
)

const banner = `
========================================================================
          Modular Monolith Blackbox DAST Scanner v1.0.0
========================================================================
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("[*] DAST Scanner v1.0.0 (Go 1.24+)")
	case "normalize":
		runNormalize(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "submit":
		runSubmit(os.Args[2:])
	case "update":
		runUpdate(os.Args[2:])
	case "api":
		runAPI(os.Args[2:])
	case "worker":
		runWorker(os.Args[2:])
	default:
		fmt.Printf("[!] 未知子命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println("[*] 用法: dast <command> [options]")
	fmt.Println("\n可用子命令:")
	fmt.Println("  scan         单机 5 阶段流水线: 目标解析->端口探活->服务探测->POC验证->报告")
	fmt.Println("  submit       向分布式 Redis Stream 投递海量原始目标 (大网段/域名列表)")
	fmt.Println("  worker       启动分布式消息消费者 Worker 节点 (支持多级流并发切片与扫描)")
	fmt.Println("  update       自动同步并拉取社区 POC 规则与敏感字典库")
	fmt.Println("  normalize    规范化解析目标并评估 Scope 策略范围")
	fmt.Println("  api          启动控制面 HTTP 服务")
	fmt.Println("  version      显示扫描器版本信息")
	fmt.Println("\n运行示例:")
	fmt.Println("  dast update --poc")
	fmt.Println("  dast scan -target \"127.0.0.1\" -profile \"fast\"")
	fmt.Println("  dast scan -target \"http://testphp.vulnweb.com\" -profile \"balanced\"")
}

func runNormalize(args []string) {
	fs := flag.NewFlagSet("normalize", flag.ExitOnError)
	targetFlag := fs.String("target", "", "待解析目标 (IP/CIDR/Domain/URL/Host:Port)")
	_ = fs.Parse(args)

	if *targetFlag == "" {
		fmt.Println("[!] 错误: 必须指定 -target 参数")
		os.Exit(1)
	}

	norm := model.ParseAndNormalizeTarget(*targetFlag)
	data, _ := json.MarshalIndent(norm, "", "  ")
	fmt.Println(string(data))
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	targetFlag := fs.String("target", "", "扫描目标 (支持多个逗号分隔: 192.168.1.1,10.0.0.1/24,example.com)")
	portsFlag := fs.String("ports", "", "指定端口范围 (如 80,443,8000-8080，留空默认使用 profile 策略)")
	profileFlag := fs.String("profile", "fast", "扫描预设 fast, balanced, deep")
	outFlag := fs.String("output", "result/scan_report.json", "JSON 审计结果保存路径")
	mdFlag := fs.String("md", "result/report.md", "Markdown 报告保存路径")
	pocDirFlag := fs.String("poc-dir", "./poc", "Nuclei POC 模板目录路径")
	_ = fs.Parse(args)

	if *targetFlag == "" {
		fmt.Println("[!] 错误: 必须指定 -target 参数")
		fs.Usage()
		os.Exit(1)
	}

	rawTargets := strings.Split(*targetFlag, ",")
	for i := range rawTargets {
		rawTargets[i] = strings.TrimSpace(rawTargets[i])
	}

	fmt.Print(banner)
	fmt.Printf("[*] 扫描启动: 目标数量=%d | Profile=%s | 端口配置=%s\n", len(rawTargets), *profileFlag, *portsFlag)
	fmt.Println("------------------------------------------------------------------------")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] 接收到中断信号，已终止扫描并立即退出。")
		cancel()
		os.Exit(0)
	}()

	cfg := config.Load()
	if *pocDirFlag != "" {
		cfg.Scan.PocDir = *pocDirFlag
	}

	scanner := portscan.NewHybridPortScanner()
	nucleiExecutor := poc.NewNucleiCheckExecutor(cfg.Scan.PocDir)
	runner := pipeline.NewRunner(scanner, nucleiExecutor, cfg.Scan.PocDir)

	scanOpts := pipeline.ScanOptions{
		Targets:      rawTargets,
		Profile:      *profileFlag,
		PortOverride: *portsFlag,
		Policy:       model.DefaultPolicy(),
		PocDir:       cfg.Scan.PocDir,
		OnProgress: func(ev pipeline.ProgressEvent) {
			prefix := fmt.Sprintf("[%d/%d]   %-24s", ev.Step, ev.TotalSteps, ev.StageName)
			fmt.Printf("%-32s | %s\n", prefix, ev.Message)
		},
	}

	result, err := runner.Run(ctx, scanOpts)
	if err != nil {
		fmt.Printf("\n[!] 扫描失败: %v\n", err)
		os.Exit(1)
	}

	printSummary(result)

	exporter := pipeline.NewReportExporter()
	if err := exporter.ExportJSON(result, *outFlag); err != nil {
		fmt.Printf("[!] 导出 JSON 报告失败: %v\n", err)
	} else {
		fmt.Printf("[+] 完整 JSON 审计报告已写入: %s\n", *outFlag)
	}

	if *mdFlag != "" {
		if err := exporter.ExportMarkdown(result, *mdFlag); err != nil {
			fmt.Printf("[!] 导出 Markdown 报告失败: %v\n", err)
		} else {
			fmt.Printf("[+] Markdown 摘要报告已写入: %s\n", *mdFlag)
		}
	}
}


func runAPI(args []string) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	portFlag := fs.Int("port", 8080, "API 监听端口")
	_ = fs.Parse(args)

	cfg := config.Load()
	scanner := portscan.NewHybridPortScanner()
	nucleiExecutor := poc.NewNucleiCheckExecutor(cfg.Scan.PocDir)
	runner := pipeline.NewRunner(scanner, nucleiExecutor, cfg.Scan.PocDir)

	server := api.NewServer(runner)
	addr := fmt.Sprintf(":%d", *portFlag)
	fmt.Printf("[*] DAST health 服务启动在 http://127.0.0.1%s\n", addr)
	_ = http.ListenAndServe(addr, server)
}

func runSubmit(args []string) {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	targetFlag := fs.String("target", "", "待投递原始目标 (支持大网段/多域名逗号分隔: 10.0.0.0/16,example.com)")
	streamFlag := fs.String("stream", mq.DefaultRawStream, "原始任务 Redis Stream")
	portFlag := fs.String("ports", "", "指定端口范围")
	profileFlag := fs.String("profile", "fast", "扫描预设 profile")
	_ = fs.Parse(args)

	if *targetFlag == "" {
		fmt.Println("[!] 错误: 必须通过 -target 指定待投递目标")
		os.Exit(1)
	}

	targets := strings.Split(*targetFlag, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	cfg := config.Load()
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	streamClient := mq.NewStreamClient(rdb)

	scanRunID := model.NewUUID()
	rawInput := mq.RawTaskInput{
		ScanRunID:  scanRunID,
		RawTargets: targets,
		PortRange:  *portFlag,
		Profile:    *profileFlag,
		ScanPolicy: model.PortScanPolicy{Profile: *profileFlag},
		RateLimit:  model.RateLimitPolicy{MaxRPS: 30, MaxConcurrentScan: 10},
		Budget:     model.BudgetPolicy{MaxDurationMinutes: 60, MaxRequestsTotal: 10000},
	}

	idempotencyKey := fmt.Sprintf("raw:%s", scanRunID)
	env, err := mq.NewEnvelope(idempotencyKey, "RawTaskInput", rawInput, 3)
	if err != nil {
		fmt.Printf("[!] 封装任务消息失败: %v\n", err)
		os.Exit(1)
	}

	msgID, err := streamClient.PublishEnvelope(context.Background(), *streamFlag, env)
	if err != nil {
		fmt.Printf("[!] 投递任务到 Redis 失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] 原始扫描任务已成功推入 Redis Stream [%s]!\n", *streamFlag)
	fmt.Printf("   - 任务批次 ID : %s\n", scanRunID)
	fmt.Printf("   - 原始目标数量 : %d (包含大网段/域名)\n", len(targets))
	fmt.Printf("   - 消息 MessageID: %s\n", msgID)
	fmt.Printf("   [*] 后台各个 Worker 将自动并发执行【分布式网段切片/域名DNS解析】并开展扫描。\n")
}

func runWorker(args []string) {
	fs := flag.NewFlagSet("worker", flag.ExitOnError)
	rawStreamFlag := fs.String("raw-stream", mq.DefaultRawStream, "原始任务 Redis Stream")
	targetStreamFlag := fs.String("target-stream", mq.DefaultTargetStream, "目标资产 Redis Stream")
	groupFlag := fs.String("group", mq.DefaultGroup, "Consumer Group 名称")
	_ = fs.Parse(args)

	cfg := config.Load()
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	scanner := portscan.NewHybridPortScanner()
	nucleiExecutor := poc.NewNucleiCheckExecutor(cfg.Scan.PocDir)
	runner := pipeline.NewRunner(scanner, nucleiExecutor, cfg.Scan.PocDir)

	worker := mq.NewWorkerRuntime(rdb, *rawStreamFlag, *targetStreamFlag, *groupFlag, runner)
	fmt.Printf("[*] 分布式 Worker 守护进程启动:\n")
	fmt.Printf("   - [层级 1] 原始解析流 (Raw Stream)   : %s\n", *rawStreamFlag)
	fmt.Printf("   - [层级 2] 扫描执行流 (Target Stream): %s\n", *targetStreamFlag)
	fmt.Printf("   - 消费组 (Consumer Group)           : %s\n", *groupFlag)
	fmt.Printf("   [*] 节点已就绪，正在监听并自动处理【分布式目标切片/DNS解析】与【5阶段漏洞扫描】...\n")
	_ = worker.Run(context.Background())
}

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	pocFlag := fs.Bool("poc", false, "同步社区 Nuclei POC 漏洞检测模板库")
	dictFlag := fs.Bool("dict", false, "同步 SecLists 敏感目录字典库")
	allFlag := fs.Bool("all", false, "同步字典库")
	pocDirFlag := fs.String("dir", "./poc", "POC 保存目录")
	_ = fs.Parse(args)

	updatePOC := *pocFlag || *allFlag || (!*dictFlag && !*pocFlag && !*allFlag)
	updateDict := *dictFlag || *allFlag

	updater := updater.NewResourceUpdater()
	ctx := context.Background()

	if updatePOC {
		if err := updater.UpdatePOCTemplates(ctx, *pocDirFlag); err != nil {
			fmt.Printf("[!] 同步 POC 规则库遇到异常: %v\n", err)
		}
	}

	if updateDict {
		if err := updater.UpdateDictionaries(ctx, "./data/dictionaries"); err != nil {
			fmt.Printf("[!] 同步字典库遇到异常: %v\n", err)
		}
	}

	fmt.Println("[+] 全部规则与资源同步流程执行完毕！")
}

func printSummary(res *pipeline.ScanResult) {
	fmt.Println("\n========================================================================")
	fmt.Println("                       [*] 扫描执行总结报告 (Summary)                      ")
	fmt.Println("========================================================================")
	fmt.Printf("任务 ID       : %s\n", res.ScanRunID)
	fmt.Printf("总耗时        : %s\n", time.Duration(res.DurationMs)*time.Millisecond)
	fmt.Printf("扫描目标数    : %d\n", res.Stats.TotalTargets)
	fmt.Printf("开放端口数    : %d\n", res.Stats.OpenPorts)
	fmt.Printf("识别服务数    : %d\n", res.Stats.ServicesFound)
	fmt.Printf("发现 Web 端点 : %d\n", res.Stats.EndpointsFound)
	fmt.Printf("确证漏洞数    : %d\n", len(res.Findings))

	if len(res.Findings) > 0 {
		fmt.Println("\n[!] 确证高风险漏洞列表:")
		for i, f := range res.Findings {
			fmt.Printf("  [%d] [%s] %s | 目标: %s\n", i+1, f.Severity, f.Title, f.MatchedAt)
		}
	} else {
		fmt.Println("\n[+] 未发现高危漏洞风险。")
	}
	fmt.Println("========================================================================")
}









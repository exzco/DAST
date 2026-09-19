package updater

import (
	"distributed-scanner/internal/domain/poc"
	"context"
	"fmt"
	"io"
	"net/http"
	"distributed-scanner/internal/infra/network"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"distributed-scanner/internal/config"

)

const (
	NucleiTemplatesRepo = "https://github.com/projectdiscovery/nuclei-templates.git"
	SecListsCommonURL   = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
)

type ResourceUpdater struct {
	httpClient *http.Client
}

func NewResourceUpdater() *ResourceUpdater {
	return &ResourceUpdater{
		httpClient: network.NewHTTPClient(30 * time.Second),
	}
}

// 更新 Nuclei poc
func (u *ResourceUpdater) UpdatePOCTemplates(ctx context.Context, pocDir string) error {
	if pocDir == "" {
		pocDir = "./poc"
	}

	absDir, err := filepath.Abs(pocDir)
	if err != nil {
		return fmt.Errorf("invalid poc dir: %w", err)
	}

	gitDir := filepath.Join(absDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		fmt.Printf("[*] 正在拉取最新的社区 POC 模板 (git pull in %s)...\n", absDir)
		cmd := exec.CommandContext(ctx, "git", "-C", absDir, "pull", "--depth", "1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("[!] git pull 执行失败: %w", err)
		}
	} else {
		_ = os.MkdirAll(filepath.Dir(absDir), 0755)
		fmt.Printf("[*] 正在从社区拉取规则模板库 (git clone %s -> %s)...\n", NucleiTemplatesRepo, absDir)
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", NucleiTemplatesRepo, absDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[!] Git 拉取失败: %v\n", err)
		}
	}

	fmt.Printf("[*] 正在构建 POC 索引 (%s -> %s)...\n", absDir, poc.DefaultPOCIndexFile)
	specs, err := poc.BuildPOCIndex(absDir, poc.DefaultPOCIndexFile)
	if err != nil {
		fmt.Printf("[!] 构建 POC 索引遇到警告: %v\n", err)
	} else {
		fmt.Printf("[+] 成功索引 %d 个社区 POC 规则\n", len(specs))
	}

	fmt.Println("[+] Nuclei 社区规则模板库同步完成")
	return nil
}

// 调度 AI 服务为指定范围的漏洞补充 POC 资源
func (u *ResourceUpdater) GenerateMissingPOCsByAI(ctx context.Context, cfg *config.Config, cveList []string) error {
	fmt.Printf("[*] 启动基于大模型与网络测绘的 POC 自动生成管线...\n")
	generator := NewAIPocGenerator(cfg)
	generator.GenerateMissingPOCs(ctx, cveList)
	fmt.Printf("[+] AI 生成的 POC 已落盘至 %s/ai_generated\n", cfg.Scan.PocDir)
	
	// 重建索引使新生成的 PoC 生效
	fmt.Printf("[*] 正在将 AI 生成的规则载入检测引擎...\n")
	poc.BuildPOCIndex(cfg.Scan.PocDir, poc.DefaultPOCIndexFile)
	return nil
}

// 更新敏感字典
func (u *ResourceUpdater) UpdateDictionaries(ctx context.Context, dictDir string) error {
	if dictDir == "" {
		dictDir = "./data/dictionaries"
	}
	_ = os.MkdirAll(dictDir, 0755)

	destFile := filepath.Join(dictDir, "paths_top1000.txt")
	fmt.Printf("[*] 正在同步 SecLists 敏感目录字典 -> %s...\n", destFile)

	req, err := http.NewRequestWithContext(ctx, "GET", SecListsCommonURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		fmt.Printf("[-] 在线下载字典遇到网络阻碍: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[!] 下载字典失败，HTTP 状态码: %d", resp.StatusCode)
	}

	out, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err == nil {
		fmt.Println("[+] 敏感字典库同步成功")
	}
	return err
}






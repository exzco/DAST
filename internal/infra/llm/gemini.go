package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"distributed-scanner/internal/infra/network"
)

// Google AI Studio (Gemini) 的底层驱动实现
type GeminiClient struct {
	endpoint   string
	apiKey     string
	model      string
	httpClient *http.Client
}

// 实例化 Gemini 驱动，强制继承全局扫描网络基建
func NewGeminiClient(endpoint, apiKey, model string, timeout time.Duration) *GeminiClient {
	if model == "" {
		model = "gemini-1.5-flash"
	}
	if endpoint == "" {
		endpoint = "https://generativelanguage.googleapis.com"
	}
	// 归一化 endpoint 去除尾部斜杠
	endpoint = strings.TrimRight(endpoint, "/")

	return &GeminiClient{
		endpoint:   endpoint,
		apiKey:     apiKey,
		model:      model,
		// 复用之前封装好的安全/防抖网络客户端
		httpClient: network.NewHTTPClient(timeout),
	}
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiConfig struct {
	ResponseMimeType string `json:"responseMimeType,omitempty"`
}

type geminiRequest struct {
	Contents         []geminiContent `json:"contents"`
	GenerationConfig geminiConfig    `json:"generationConfig,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// 发起 API 请求，利用 Gemini 原生配置强制输出结构化 JSON 数据
func (c *GeminiClient) GenerateJSON(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s", c.endpoint, c.model, c.apiKey)

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: geminiConfig{
			// 核心降维逻辑：禁止大模型输出自然语言废话，强制只返回 JSON
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// 依赖底层的强健网络设施发起调用（支持代理、超时熔断）
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var gResp geminiResponse
	if err := json.Unmarshal(respBytes, &gResp); err != nil {
		return "", fmt.Errorf("gemini api decode error: %w\nRaw: %s", err, string(respBytes))
	}

	if gResp.Error != nil {
		return "", fmt.Errorf("gemini api failure: %s", gResp.Error.Message)
	}

	if len(gResp.Candidates) == 0 || len(gResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned empty payload")
	}

	return gResp.Candidates[0].Content.Parts[0].Text, nil
}

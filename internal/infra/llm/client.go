package llm

import "context"

type Inferencer interface {
	// 强制大模型根据 prompt 推理，并严格返回纯 JSON 格式的字符串。
	GenerateJSON(ctx context.Context, prompt string) (string, error)
}

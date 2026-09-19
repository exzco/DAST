package fingerprint

import (
    "distributed-scanner/internal/infra/llm"
)

type ServiceEvidenceResolver struct {}

func NewServiceEvidenceResolver(client llm.LLMClient) *ServiceEvidenceResolver {
    return &ServiceEvidenceResolver{}
}

func (s *ServiceEvidenceResolver) Resolve(host string, port int, banner string) string {
    // todo...
    return ""
}

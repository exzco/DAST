package updater

import "context"

type AIPocGenerator struct {}

func NewAIPocGenerator(cfg interface{}) *AIPocGenerator {
    return &AIPocGenerator{}
}

func (g *AIPocGenerator) GenerateMissingPOCs(ctx context.Context, cveList []string) {
    // todo...
}

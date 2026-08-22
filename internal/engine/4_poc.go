// Package engine provides core scanning and POC execution logic.
package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"distributed-scanner/internal/model"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)


type RuleIndex struct {
	mu         sync.RWMutex
	specs      []model.CheckSpec
	byProtocol map[string][]int
	byProduct  map[string][]int
	byTag      map[string][]int
}

func NewRuleIndex() *RuleIndex {
	return &RuleIndex{
		byProtocol: make(map[string][]int),
		byProduct:  make(map[string][]int),
		byTag:      make(map[string][]int),
	}
}

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

		if pol != nil {
			if spec.IntrusiveLevel == model.IntrusiveLevelIntrusive && pol.IntrusiveLevel != model.IntrusiveLevelIntrusive {
				continue
			}
			hasDeniedTag := false
			for _, dt := range pol.DeniedTags {
				for _, st := range spec.Tags {
					if strings.EqualFold(dt, st) {
						hasDeniedTag = true
						break
					}
				}
				if hasDeniedTag {
					break
				}
			}
			if hasDeniedTag {
				continue
			}
		}
		selected = append(selected, spec)
	}
	return selected
}

type NucleiCheckExecutor struct {
	pocDir string
}

func NewNucleiCheckExecutor(pocDir string) *NucleiCheckExecutor {
	return &NucleiCheckExecutor{pocDir: pocDir}
}

// ExecuteCheck directly uses the standard Nuclei SDK engine to execute templates without custom wrappers.
func (e *NucleiCheckExecutor) ExecuteCheck(ctx context.Context, spec model.CheckSpec, targetCtx CheckContext) ([]model.Finding, error) {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
	}

	if len(spec.Tags) > 0 {
		opts = append(opts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Tags: spec.Tags,
		}))
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create nuclei engine: %w", err)
	}
	defer ne.Close()

	if e.pocDir != "" {
		ne.LoadTargets([]string{targetCtx.TargetURL}, false)
	}

	var findings []model.Finding
	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}

		evidenceHash := model.HashContent([]byte(event.Response))
		f := model.Finding{
			ID:           model.NewUUID(),
			TenantID:     targetCtx.Policy.TenantID,
			ScanRunID:    targetCtx.ScanRunID,
			Title:        event.Info.Name,
			Description:  event.Info.Description,
			Severity:     mapNucleiSeverity(event.Info.SeverityHolder.Severity.String()),
			Confidence:   model.ConfidenceCertain,
			State:        model.FindingStateConfirmed,
			CheckID:      spec.ID,
			MatchedAt:    event.Matched,
			EvidenceRefs: []string{evidenceHash},
			Verified:     true,
			FirstSeen:    time.Now().UTC(),
			LastSeen:     time.Now().UTC(),
		}
		findings = append(findings, f)
	})

	if err != nil {
		return nil, fmt.Errorf("execute nuclei check: %w", err)
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

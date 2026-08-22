package distributed

import (
	"encoding/json"
	"fmt"
	"time"

	"distributed-scanner/internal/model"
)

type RawTaskInput struct {
	ScanRunID   string                `json:"scan_run_id"`
	RawTargets  []string              `json:"raw_targets"`
	PortRange   string                `json:"port_range,omitempty"`
	Profile     string                `json:"profile,omitempty"`
	ScanPolicy  model.PortScanPolicy  `json:"scan_policy"`
	RateLimit   model.RateLimitPolicy `json:"rate_limit"`
	Budget      model.BudgetPolicy    `json:"budget"`
	PayloadData map[string]string     `json:"payload_data,omitempty"`
}

type StageInput struct {
	ScanRunID   string               `json:"scan_run_id"`
	StageRunID  string               `json:"stage_run_id"`
	StageName   string               `json:"stage_name"`
	Target      string               `json:"target"`
	Port        int                  `json:"port,omitempty"`
	PortRange   string               `json:"port_range,omitempty"`
	ScanPolicy  model.PortScanPolicy `json:"scan_policy"`
	RateLimit   model.RateLimitPolicy`json:"rate_limit"`
	Budget      model.BudgetPolicy   `json:"budget"`
	PayloadData map[string]string    `json:"payload_data,omitempty"`
}

type StageOutput struct {
	ScanRunID    string                  `json:"scan_run_id"`
	StageRunID   string                  `json:"stage_run_id"`
	StageName    string                  `json:"stage_name"`
	Success      bool                    `json:"success"`
	ErrorClass   model.ErrorClass        `json:"error_class,omitempty"`
	ErrorMessage string                  `json:"error_message,omitempty"`
	Observations []model.PortObservation `json:"observations,omitempty"`
	Services     []model.Service         `json:"services,omitempty"`
	Findings     []model.Finding         `json:"findings,omitempty"`
	DurationMs   int64                   `json:"duration_ms"`
}

type MessageEnvelope struct {
	ID             string          `json:"id"`
	SchemaVersion  string          `json:"schema_version"`
	TraceID        string          `json:"trace_id"`
	Timestamp      time.Time       `json:"timestamp"`
	IdempotencyKey string          `json:"idempotency_key"`
	Attempt        int             `json:"attempt"`
	MaxAttempts    int             `json:"max_attempts"`
	PayloadType    string          `json:"payload_type"`
	Payload        json.RawMessage `json:"payload"`
}

func NewEnvelope(idempotencyKey string, payloadType string, payload any, maxAttempts int) (*MessageEnvelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	return &MessageEnvelope{
		ID:             model.NewUUID(),
		SchemaVersion:  "v1.0.0",
		TraceID:        model.NewUUID(),
		Timestamp:      model.NowUTC(),
		IdempotencyKey: idempotencyKey,
		Attempt:        1,
		MaxAttempts:    maxAttempts,
		PayloadType:    payloadType,
		Payload:        data,
	}, nil
}

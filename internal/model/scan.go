package model

import "time"

type ScanRunStats struct {
	TotalTargets   int   `json:"total_targets"`
	ScannedTargets int   `json:"scanned_targets"`
	OpenPorts      int   `json:"open_ports"`
	ServicesFound  int   `json:"services_found"`
	EndpointsFound int   `json:"endpoints_found"`
	FindingsCount  int   `json:"findings_count"`
	DurationMs     int64 `json:"duration_ms"`
}

type ScanRun struct {
	ID             string        `json:"id"`
	ProjectID      string        `json:"project_id"`
	Name           string        `json:"name"`
	State          ScanState     `json:"state"`
	PolicySnapshot *Policy       `json:"policy_snapshot"`
	Stats          ScanRunStats  `json:"stats"`
	CreatedBy      string        `json:"created_by"`
	StartedAt      *time.Time    `json:"started_at,omitempty"`
	CompletedAt    *time.Time    `json:"completed_at,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

type StageRun struct {
	ID             string     `json:"id"`
	ScanRunID      string     `json:"scan_run_id"`
	ParentStageID  string     `json:"parent_stage_id,omitempty"`
	StageName      string     `json:"stage_name"`
	AssetKey       string     `json:"asset_key,omitempty"`
	State          StageState `json:"state"`
	IdempotencyKey string     `json:"idempotency_key"`
	Attempt        int        `json:"attempt"`
	MaxAttempts    int        `json:"max_attempts"`
	ErrorClass     ErrorClass `json:"error_class,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Prerequisite struct {
	Protocols []string `json:"protocols,omitempty"`
	Products  []string `json:"products,omitempty"`
}

type CheckSpec struct {
	ID             string         `json:"id"`
	FilePath       string         `json:"file_path"`
	Name           string         `json:"name"`
	CheckType      CheckType      `json:"check_type"`
	Severity       Severity       `json:"severity"`
	Prerequisites  Prerequisite   `json:"prerequisites"`
	Tags           []string       `json:"tags"`
	TimeoutSec     int            `json:"timeout_sec"`
	Version        string         `json:"version"`
}

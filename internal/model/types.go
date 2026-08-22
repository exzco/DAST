package model

import (
	"crypto/rand"
	"fmt"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Confidence float64

const (
	ConfidenceCertain   Confidence = 1.0
	ConfidenceFirm      Confidence = 0.8
	ConfidenceTentative Confidence = 0.5
	ConfidenceUnknown   Confidence = 0.0
)

type ScanState string

const (
	ScanStateDraft     ScanState = "DRAFT"
	ScanStatePending   ScanState = "PENDING"
	ScanStateRunning   ScanState = "RUNNING"
	ScanStateCompleted ScanState = "COMPLETED"
	ScanStateFailed    ScanState = "FAILED"
	ScanStateCancelled ScanState = "CANCELLED"
)

type StageState string

const (
	StageStatePending   StageState = "PENDING"
	StageStateReady     StageState = "READY"
	StageStateRunning   StageState = "RUNNING"
	StageStateSucceeded StageState = "SUCCEEDED"
	StageStateFailed    StageState = "FAILED"
	StageStateSkipped   StageState = "SKIPPED"
)

type ErrorClass string

const (
	ErrorClassTimeout     ErrorClass = "TIMEOUT"
	ErrorClassNetwork     ErrorClass = "NETWORK_ERROR"
	ErrorClassParseError  ErrorClass = "PARSE_ERROR"
	ErrorClassPolicyDeny  ErrorClass = "POLICY_DENIED"
	ErrorClassToolError   ErrorClass = "TOOL_ERROR"
	ErrorClassInternal    ErrorClass = "INTERNAL_ERROR"
)

type AppError struct {
	Class   ErrorClass `json:"class"`
	Message string     `json:"message"`
	Err     error      `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Class, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Class, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func NewAppError(class ErrorClass, message string, err error) *AppError {
	return &AppError{
		Class:   class,
		Message: message,
		Err:     err,
	}
}

func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func NowUTC() time.Time {
	return time.Now().UTC()
}

var ErrNotFound = fmt.Errorf("entity not found")

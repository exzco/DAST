package storage

import (
	"context"
	"sync"

	"distributed-scanner/internal/model"
)

type MemoryStore struct {
	mu       sync.RWMutex
	runs     map[string]*model.ScanRun
	findings map[string]model.Finding
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		runs:     make(map[string]*model.ScanRun),
		findings: make(map[string]model.Finding),
	}
}

func (s *MemoryStore) SaveScanRun(ctx context.Context, run *model.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[run.ID] = run
	return nil
}

func (s *MemoryStore) GetScanRun(ctx context.Context, id string) (*model.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, exists := s.runs[id]
	if !exists {
		return nil, model.ErrNotFound
	}
	return run, nil
}

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"distributed-scanner/internal/model"
)

type FileStore struct {
	mu      sync.RWMutex
	baseDir string
}

func NewFileStore(baseDir string) (*FileStore, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base dir: %w", err)
	}
	return &FileStore{baseDir: baseDir}, nil
}

func (s *FileStore) SaveScanRun(ctx context.Context, run *model.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.baseDir, "runs")
	_ = os.MkdirAll(dir, 0755)

	filePath := filepath.Join(dir, fmt.Sprintf("%s.json", run.ID))
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

func (s *FileStore) GetScanRun(ctx context.Context, id string) (*model.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := filepath.Join(s.baseDir, "runs", fmt.Sprintf("%s.json", id))
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}

	var run model.ScanRun
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

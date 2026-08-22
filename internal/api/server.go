package api
// 目前感觉就是看看这个 work node 还存没存活
import (
	"context"
	"encoding/json"
	"net/http"

	"distributed-scanner/internal/engine"
	"distributed-scanner/internal/model"
)

type Server struct {
	runner *engine.Runner
	mux    *http.ServeMux
}

func NewServer(runner *engine.Runner) *Server {
	s := &Server{
		runner: runner,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

type CreateScanRequest struct {
	Targets []string `json:"targets"`
	Profile string   `json:"profile"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets cannot be empty", http.StatusBadRequest)
		return
	}

	res, err := s.runner.Run(context.Background(), engine.ScanOptions{
		Targets: req.Targets,
		Profile: req.Profile,
		Policy:  model.DefaultPolicy("api-tenant"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(res)
}

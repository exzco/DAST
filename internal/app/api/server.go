package api
// 查询 work node health
import (
	"encoding/json"
	"net/http"

	"distributed-scanner/pkg/pipeline"
)

type Server struct {
	runner *pipeline.Runner
	mux    *http.ServeMux
}

func NewServer(runner *pipeline.Runner) *Server {
	s := &Server{
		runner: runner,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
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





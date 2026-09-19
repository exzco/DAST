package model

type ProbeRequest struct {
	Host       string               `json:"host"`
	Port       int                  `json:"port,omitempty"`
	Transport  string               `json:"transport"`
	PortRange  string               `json:"port_range,omitempty"`
	ScanPolicy PortScanPolicy       `json:"scan_policy"`
}

type CheckContext struct {
	ScanRunID   string        `json:"scan_run_id"`
	TargetURL   string        `json:"target_url"`
	ServiceHost string        `json:"service_host"`
	ServicePort int           `json:"service_port"`
	Protocol    string        `json:"protocol"`
	Facts       []Fact        `json:"facts"`
	Policy      *Policy       `json:"policy"`
}

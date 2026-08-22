package engine

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"distributed-scanner/internal/model"

	nmap "github.com/Ullaakut/nmap/v3"
)

var CommonTop100Ports = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143, 161, 389,
	443, 445, 465, 500, 514, 587, 636, 873, 993, 995, 1025, 1080, 1099, 1433, 1521,
	2049, 2181, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 4369, 5000, 5432, 5672,
	5900, 5984, 6379, 6443, 7001, 7077, 7890, 8000, 8008, 8080, 8081, 8082, 8083,
	8084, 8085, 8088, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
	10000, 11211, 15672, 27017, 27018, 28017, 33060, 50000, 50070,
}

type NativePortScanner struct{}

func NewNativePortScanner() *NativePortScanner {
	return &NativePortScanner{}
}

func (s *NativePortScanner) ScanPorts(ctx context.Context, req ProbeRequest) ([]model.PortObservation, error) {
	start := time.Now()
	ports := ParsePortRange(req.PortRange)
	// 自实现端口探测
	openPorts, err := NativeGoScan(ctx, req.Host, ports, 150, 400*time.Millisecond)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return nil, err
	}

	observations := make([]model.PortObservation, 0, len(openPorts))
	for _, p := range openPorts {
		observations = append(observations, model.PortObservation{
			Host:        strings.ToLower(req.Host),
			Port:        p,
			Transport:   "tcp",
			Status:      model.PortStatusOpen,
			DurationMs:  duration,
			ProbeSource: "native_tcp",
			ObservedAt:  time.Now().UTC(),
		})
	}
	return observations, nil
}

func NativeGoScan(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration) ([]int, error) {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}

	portsChan := make(chan int, len(ports))
	resultsChan := make(chan int, len(ports))
	// 并发
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portsChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := net.JoinHostPort(host, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					_ = conn.Close()
					resultsChan <- p
				}
			}
		}()
	}

	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	wg.Wait()
	close(resultsChan)

	var openPorts []int
	for p := range resultsChan {
		openPorts = append(openPorts, p)
	}
	return openPorts, nil
}

func ParsePortRange(portRange string) []int {
	portRange = strings.TrimSpace(portRange)
	if portRange == "" || portRange == "top100" {
		return CommonTop100Ports
	}
	if portRange == "top1000" {
		portsMap := make(map[int]bool)
		for _, p := range CommonTop100Ports {
			portsMap[p] = true
		}
		for p := 1; p <= 1024; p++ {
			portsMap[p] = true
		}
		var list []int
		for p := range portsMap {
			list = append(list, p)
		}
		return list
	}

	var result []int
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			subParts := strings.Split(part, "-")
			if len(subParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(subParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(subParts[1]))
				if err1 == nil && err2 == nil && start > 0 && end >= start && end <= 65535 {
					for p := start; p <= end; p++ {
						result = append(result, p)
					}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				result = append(result, p)
			}
		}
	}

	if len(result) == 0 {
		return CommonTop100Ports
	}
	return result
}


type NmapProbeAdapter struct{}

func (a *NmapProbeAdapter) ScanPorts(ctx context.Context, req ProbeRequest) ([]model.PortObservation, error) {
	opts := []nmap.Option{
		nmap.WithTargets(req.Host),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithConnectScan(),
	}
	if req.PortRange != "" && req.PortRange != "top1000" && req.PortRange != "top100" {
		opts = append(opts, nmap.WithPorts(req.PortRange))
	} else {
		opts = append(opts, nmap.WithMostCommonPorts(100))
	}

	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		return nil, err
	}
	result, _, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	var observations []model.PortObservation
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				observations = append(observations, model.PortObservation{
					Host:        req.Host,
					Port:        int(port.ID),
					Transport:   "tcp",
					Status:      model.PortStatusOpen,
					ProbeSource: "nmap",
					ObservedAt:  time.Now().UTC(),
				})
			}
		}
	}
	return observations, nil
}

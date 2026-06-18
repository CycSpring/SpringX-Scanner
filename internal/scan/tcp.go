package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

type portJob struct {
	host string
	port int
}

func ScanPorts(ctx context.Context, hosts []string, ports []int, concurrency int, timeout time.Duration, proxy string, onOpen func(model.Service)) []model.Service {
	jobs := make(chan portJob)
	results := make(chan model.Service)
	var wg sync.WaitGroup

	workerCount := concurrency
	if workerCount < 1 {
		workerCount = 1
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if !isPortOpen(ctx, job.host, job.port, timeout) {
					continue
				}
				svc := ProbeHTTPService(ctx, job.host, job.port, timeout, proxy)
				if svc.Host == "" {
					svc.Host = job.host
				}
				if svc.Port == 0 {
					svc.Port = job.port
				}
				if svc.Protocol == "" {
					svc.Protocol = serviceName(job.port)
				}
				results <- svc
				if onOpen != nil {
					onOpen(svc)
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- portJob{host: host, port: port}:
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var services []model.Service
	for svc := range results {
		services = append(services, svc)
	}
	return services
}

func isPortOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

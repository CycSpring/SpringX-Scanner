package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
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
				open, banner := isPortOpen(ctx, job.host, job.port, timeout)
				if !open {
					continue
				}
				svc := ProbeHTTPService(ctx, job.host, job.port, timeout, proxy)
				// Only attach the TCP banner when the HTTP probe did not yield a
				// real service, so we never overwrite HTTP-derived fields.
				if svc.StatusCode <= 0 && svc.Error != "" {
					svc.Banner = banner
				}
				if svc.Host == "" {
					svc.Host = job.host
				}
				if svc.Port == 0 {
					svc.Port = job.port
				}
				if svc.Protocol == "" {
					svc.Protocol = serviceName(job.port)
				}
				select {
				case results <- svc:
				case <-ctx.Done():
					return
				}
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

// isPortOpen dials a TCP port and, on success, attempts to read a service
// greeting banner (e.g. SSH/FTP/SMTP/MySQL/Redis). It returns (open, banner).
// The banner read uses a short deadline so it does not stall port scanning on
// silent services; an empty banner means no greeting was sent.
func isPortOpen(ctx context.Context, host string, port int, timeout time.Duration) (bool, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, ""
	}
	banner := grabBanner(conn, timeout)
	_ = conn.Close()
	return true, banner
}

// grabBanner reads up to 256 bytes of a service greeting with a short deadline
// (half the dial timeout, capped at 2s) so connection-oriented protocols like
// SSH/FTP/SMTP/MySQL/Redis that send a banner on connect are captured without
// delaying silent services. The result is trimmed of control characters and
// truncated to 200 bytes for display.
func grabBanner(conn net.Conn, dialTimeout time.Duration) string {
	readDeadline := dialTimeout / 2
	if readDeadline <= 0 || readDeadline > 2*time.Second {
		readDeadline = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	b := strings.ToValidUTF8(string(buf[:n]), "")
	b = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, b)
	b = strings.TrimSpace(strings.ReplaceAll(b, "\t", " "))
	if len(b) > 200 {
		b = b[:200]
	}
	return b
}

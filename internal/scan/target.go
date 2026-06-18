package scan

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Targets struct {
	URLs  []string
	Hosts []string
}

func ResolveTargets(cfg Config) (Targets, error) {
	var out Targets
	limit := cfg.TargetLimit()

	addURL := func(value string) error {
		normalized, err := NormalizeURL(value)
		if err != nil {
			return err
		}
		out.URLs = appendUnique(out.URLs, normalized)
		return nil
	}
	addHost := func(value string) {
		for _, item := range splitTargetList(value) {
			out.Hosts = appendUnique(out.Hosts, item)
		}
	}

	if cfg.TargetURL != "" {
		if err := addURL(cfg.TargetURL); err != nil {
			return out, err
		}
	}
	if cfg.URLFile != "" {
		lines, err := readLines(cfg.URLFile, limit)
		if err != nil {
			return out, err
		}
		for _, line := range lines {
			if err := addURL(line); err != nil {
				return out, err
			}
		}
	}
	if cfg.TargetIP != "" {
		hosts, err := expandHosts(cfg.TargetIP, limit)
		if err != nil {
			return out, err
		}
		for _, host := range hosts {
			addHost(host)
		}
	}
	if cfg.IPFile != "" {
		lines, err := readLines(cfg.IPFile, limit)
		if err != nil {
			return out, err
		}
		for _, line := range lines {
			hosts, err := expandHosts(line, limit-len(out.Hosts))
			if err != nil {
				return out, err
			}
			for _, host := range hosts {
				addHost(host)
			}
			if len(out.Hosts) >= limit {
				break
			}
		}
	}
	if len(out.URLs) == 0 && len(out.Hosts) == 0 {
		return out, fmt.Errorf("no scan targets provided")
	}
	return out, nil
}

func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", raw)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func readLines(path string, limit int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	return lines, scanner.Err()
}

func splitTargetList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func expandHosts(value string, limit int) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var out []string
	for _, item := range splitTargetList(value) {
		if strings.Contains(item, "/") {
			ips, err := expandCIDR(item, limit-len(out))
			if err != nil {
				return nil, err
			}
			out = append(out, ips...)
			continue
		}
		out = append(out, item)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func expandCIDR(cidr string, limit int) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var out []string
	for current := ip.Mask(network.Mask); network.Contains(current); current = nextIP(current) {
		if current.IsUnspecified() {
			continue
		}
		out = append(out, current.String())
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func nextIP(ip net.IP) net.IP {
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

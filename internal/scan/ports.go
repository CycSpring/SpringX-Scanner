package scan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var commonPorts = []int{
	80, 443, 8080, 8443, 8000, 8008, 8888, 8081, 8082, 3000,
	5000, 7001, 9000, 9001, 9090, 9443, 81, 82, 83, 84,
	85, 86, 87, 88, 89, 90, 110, 143, 389, 636,
	21, 22, 23, 25, 53, 67, 68, 69, 111, 123,
	135, 137, 138, 139, 161, 162, 179, 389, 445, 465,
	514, 515, 587, 593, 631, 873, 902, 993, 995, 1025,
	1080, 1099, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375,
	2376, 3306, 3389, 3690, 4443, 4567, 5432, 5601, 5672, 5900,
	5985, 5986, 6379, 6443, 7000, 7474, 7777, 8009, 8069, 8090,
	8091, 8099, 8161, 8200, 8500, 8834, 8880, 9200, 9300, 9418,
	10000, 11211, 15672, 27017, 27018, 27019, 28017, 50070, 50075, 61616,
	62078,
}

func ParsePorts(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "TOP100"
	}
	upper := strings.ToUpper(value)
	switch upper {
	case "TOP100", "TOP":
		ports := uniqueSorted(commonPorts)
		return ports[:min(100, len(ports))], nil
	case "TOP500":
		ports := uniqueSorted(commonPorts)
		for p := 1; len(ports) < 500 && p <= 65535; p++ {
			ports = append(ports, p)
		}
		return uniqueSorted(ports[:min(500, len(ports))]), nil
	case "ALL":
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	var ports []int
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			start, err := parsePort(parts[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			continue
		}
		port, err := parsePort(item)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", value)
	}
	return uniqueSorted(ports), nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range %d", port)
	}
	return port, nil
}

func uniqueSorted(values []int) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, value := range values {
		if value < 1 || value > 65535 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

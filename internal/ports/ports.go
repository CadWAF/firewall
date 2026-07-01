package ports

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseList parses a comma-separated port list. Each item may be a single port
// or an inclusive range using "-" or "_" (CSF-style), e.g. "22,80-443,8080".
func ParseList(s string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var ports []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := parseToken(part)
		if err != nil {
			return nil, err
		}
		ports = append(ports, parsed...)
	}
	return ports, nil
}

func parseToken(part string) ([]uint16, error) {
	for _, sep := range []string{"-", "_"} {
		if strings.Contains(part, sep) {
			return expandRange(part, sep)
		}
	}
	p, err := strconv.ParseUint(part, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", part)
	}
	return []uint16{uint16(p)}, nil
}

func expandRange(s, sep string) ([]uint16, error) {
	parts := strings.SplitN(s, sep, 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	if hi < lo {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	ports := make([]uint16, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

// FormatList renders ports as a comma-separated list (no range compression).
func FormatList(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

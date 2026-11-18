package parser

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/huzenkon/waf-firewall/internal/ports"
)

const MaxPortsPerRule = 15
const MaxRules = 64

type EntryKind int

const (
	EntrySimpleIP EntryKind = iota
	EntryComplexRule
)

type Protocol int

const (
	ProtoTCP Protocol = iota + 1
	ProtoUDP
	ProtoICMP
)

type Direction int

const (
	DirIn Direction = iota + 1
	DirOut
)

type Action int

const (
	ActionPass Action = iota + 1
	ActionDrop
)

type PortSpec int

const (
	PortNone PortSpec = iota
	PortSrc
	PortDst
)

type IPSpec int

const (
	IPNone IPSpec = iota
	IPSrc
	IPDst
)

type UIDGIDType int

const (
	UIDGIDNone UIDGIDType = iota
	UIDGIDUID
	UIDGIDGID
)

type Entry struct {
	Kind      EntryKind
	File      string
	Line      int
	Raw       string
	IP        net.IP
	PrefixLen int

	Proto      Protocol
	Direction  Direction
	Action     Action
	PortSpec   PortSpec
	IPSpec     IPSpec
	Ports      []uint16
	UIDGIDType UIDGIDType
	UIDGID     uint32
}

func ParseFile(path string, action Action) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := ParseLine(line, action)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		e.File = path
		e.Line = lineNo
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

func ParseLine(line string, defaultAction Action) (Entry, error) {
	e := Entry{Raw: line, Action: defaultAction}
	if strings.Contains(line, "|") {
		return parseComplexRule(line, defaultAction)
	}
	ip, network, err := net.ParseCIDR(line)
	if err == nil {
		e.Kind = EntrySimpleIP
		e.IP = ip
		ones, _ := network.Mask.Size()
		e.PrefixLen = ones
		return e, nil
	}
	parsed := net.ParseIP(line)
	if parsed == nil {
		return Entry{}, fmt.Errorf("invalid IP or rule: %q", line)
	}
	e.Kind = EntrySimpleIP
	e.IP = parsed
	if parsed.To4() != nil {
		e.PrefixLen = 32
	} else {
		e.PrefixLen = 128
	}
	return e, nil
}

func parseComplexRule(line string, defaultAction Action) (Entry, error) {
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return Entry{}, fmt.Errorf("invalid complex rule: %q", line)
	}

	e := Entry{
		Kind:       EntryComplexRule,
		Raw:        line,
		Action:     defaultAction,
		PortSpec:   PortNone,
		IPSpec:     IPNone,
		UIDGIDType: UIDGIDNone,
	}

	switch strings.ToLower(parts[0]) {
	case "tcp":
		e.Proto = ProtoTCP
	case "udp":
		e.Proto = ProtoUDP
	case "icmp":
		e.Proto = ProtoICMP
	default:
		return Entry{}, fmt.Errorf("unknown protocol %q", parts[0])
	}

	switch strings.ToLower(parts[1]) {
	case "in":
		e.Direction = DirIn
	case "out":
		e.Direction = DirOut
	default:
		return Entry{}, fmt.Errorf("unknown direction %q", parts[1])
	}

	for _, part := range parts[2:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "s=") || strings.HasPrefix(part, "d=") {
			val := part[2:]
			if isPortField(part) {
				parsed, err := ports.ParseList(val)
				if err != nil {
					return Entry{}, err
				}
				e.Ports = parsed
				if strings.HasPrefix(part, "s=") {
					e.PortSpec = PortSrc
				} else {
					e.PortSpec = PortDst
				}
				continue
			}
			ip, prefix, err := parseIPSpec(val)
			if err != nil {
				return Entry{}, err
			}
			e.IP = ip
			e.PrefixLen = prefix
			if strings.HasPrefix(part, "s=") {
				e.IPSpec = IPSrc
			} else {
				e.IPSpec = IPDst
			}
			continue
		}
		if strings.HasPrefix(part, "u=") {
			if e.Direction != DirOut {
				return Entry{}, fmt.Errorf("uid rules only apply to outgoing connections")
			}
			uid, err := strconv.ParseUint(strings.TrimPrefix(part, "u="), 10, 32)
			if err != nil {
				return Entry{}, fmt.Errorf("invalid uid: %w", err)
			}
			e.UIDGIDType = UIDGIDUID
			e.UIDGID = uint32(uid)
			continue
		}
		if strings.HasPrefix(part, "g=") {
			if e.Direction != DirOut {
				return Entry{}, fmt.Errorf("gid rules only apply to outgoing connections")
			}
			gid, err := strconv.ParseUint(strings.TrimPrefix(part, "g="), 10, 32)
			if err != nil {
				return Entry{}, fmt.Errorf("invalid gid: %w", err)
			}
			e.UIDGIDType = UIDGIDGID
			e.UIDGID = uint32(gid)
			continue
		}
		return Entry{}, fmt.Errorf("unknown field %q", part)
	}

	if e.UIDGIDType != UIDGIDNone && e.IPSpec != IPNone {
		// CSF: uid/gid implies outgoing, s/d IP ignored — we allow but ignore IP in compiler.
	}

	return e, nil
}

func isPortField(part string) bool {
	val := part[2:]
	if strings.Contains(val, ".") || strings.Contains(val, ":") {
		return false
	}
	if _, err := strconv.ParseUint(val, 10, 16); err == nil {
		return true
	}
	if strings.Contains(val, ",") || strings.Contains(val, "_") || strings.Contains(val, "-") {
		return true
	}
	return false
}

func parsePorts(val string) ([]uint16, error) {
	return ports.ParseList(val)
}

func parseIPSpec(val string) (net.IP, int, error) {
	if strings.Contains(val, "/") {
		ip, network, err := net.ParseCIDR(val)
		if err != nil {
			return nil, 0, err
		}
		ones, _ := network.Mask.Size()
		return ip, ones, nil
	}
	ip := net.ParseIP(val)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP %q", val)
	}
	if ip.To4() != nil {
		return ip, 32, nil
	}
	return ip, 128, nil
}

func AppendIPToFile(path string, ip string) error {
	entries, err := ParseFile(path, ActionPass)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Kind == EntrySimpleIP && e.Raw == ip {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", ip)
	return err
}

func RemoveIPFromFile(path string, ip string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == ip {
			continue
		}
		out = append(out, line)
	}
	return writeLines(path, out)
}

func AppendRuleToFile(path string, rule string) error {
	_, err := ParseLine(rule, ActionPass)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", rule)
	return err
}

func RemoveRuleFromFile(path string, index int) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	ruleIdx := 0
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "|") {
			if ruleIdx == index {
				ruleIdx++
				continue
			}
			ruleIdx++
		}
		out = append(out, line)
	}
	return writeLines(path, out)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0644)
}

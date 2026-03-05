package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pwnbox/net_scan/internal/models"
)

// SharpScanResult holds parsed SharpScan output.
type SharpScanResult struct {
	SourceIP       string
	SourceHostname string
	Hosts          []models.Host
}

// ParseSharpScanFile parses a SharpScan output file.
func ParseSharpScanFile(path string) (*SharpScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sharpscan file %s: %w", path, err)
	}
	defer f.Close()
	return ParseSharpScan(f)
}

// ParseSharpScan parses SharpScan text output from a reader.
//
// Format:
//
//	# 192.168.1.5 / WEB05
//	192.168.1.10:80,445
//	192.168.1.11:22,3389
func ParseSharpScan(r io.Reader) (*SharpScanResult, error) {
	result := &SharpScanResult{}
	hostMap := map[string]*models.Host{}
	var hostOrder []string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Header line: # $ip / $hostname
		if strings.HasPrefix(line, "#") {
			parts := strings.SplitN(strings.TrimPrefix(line, "#"), "/", 2)
			result.SourceIP = strings.TrimSpace(parts[0])
			if len(parts) == 2 {
				result.SourceHostname = strings.TrimSpace(parts[1])
			}
			continue
		}

		// IP:port1,port2,...
		colonIdx := strings.LastIndex(line, ":")
		if colonIdx < 0 {
			continue
		}
		ip := line[:colonIdx]
		portList := line[colonIdx+1:]

		if _, exists := hostMap[ip]; !exists {
			source := result.SourceHostname
			if source == "" {
				source = result.SourceIP
			}
			if source == "" {
				source = "sharpscan"
			}
			hostMap[ip] = &models.Host{IP: ip, Source: source}
			hostOrder = append(hostOrder, ip)
		}

		for _, portStr := range strings.Split(portList, ",") {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			hostMap[ip].Ports = append(hostMap[ip].Ports, models.OpenPort{
				Port:     portNum,
				Protocol: "tcp",
				State:    "open",
				Source:   hostMap[ip].Source,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read sharpscan: %w", err)
	}

	for _, ip := range hostOrder {
		result.Hosts = append(result.Hosts, *hostMap[ip])
	}
	return result, nil
}

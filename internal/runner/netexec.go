package runner

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strings"
)

// SMBInfo holds Windows host metadata extracted from a netexec SMB probe.
type SMBInfo struct {
	Name   string // NetBIOS/AD computer name (e.g. "WEB04")
	Domain string // Windows domain (e.g. "cowmotors.com")
	OS     string // OS description (e.g. "Windows 10 / Server 2019 Build 17763 x64")
}

var (
	reNxcName   = regexp.MustCompile(`\(name:([^)]+)\)`)
	reNxcDomain = regexp.MustCompile(`\(domain:([^)]+)\)`)
	// OS string sits between "[*] " and the first " (" parenthesis block.
	reNxcOS = regexp.MustCompile(`\[\*\]\s+(.+?)\s+\(`)
)

// RunNxcSMB probes a host on port 445 using netexec (nxc) and returns the
// computer name, domain, and OS string extracted from the SMB negotiation.
// No authentication is required — the data comes from the SMB negotiate response.
//
// Returns (nil, nil) if nxc is not installed or the banner cannot be parsed.
// When proxychainsConf is non-empty, the command is run through proxychains.
func RunNxcSMB(ip, proxychainsConf string) (*SMBInfo, error) {
	nxcBin, err := exec.LookPath("nxc")
	if err != nil {
		return nil, nil // nxc not installed; caller should skip silently
	}

	args := buildNxcArgs(nxcBin, proxychainsConf, ip)
	var out bytes.Buffer
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &out
	// nxc writes progress/status to stderr; discard to keep output clean.
	cmd.Stderr = nil
	// Ignore exit code: nxc exits non-zero on auth failure but the SMB banner
	// line is still printed (it's captured before any auth attempt).
	_ = cmd.Run()

	return parseNxcSMBOutput(out.String()), nil
}

func buildNxcArgs(nxcBin, proxychainsConf, ip string) []string {
	var args []string
	if proxychainsConf != "" {
		args = append(args, proxychainsPrefix(proxychainsConf)...)
	}
	args = append(args, nxcBin, "smb", ip)
	return args
}

func parseNxcSMBOutput(output string) *SMBInfo {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "SMB") || !strings.Contains(trimmed, "[*]") {
			continue
		}

		info := &SMBInfo{}

		if m := reNxcName.FindStringSubmatch(line); m != nil {
			info.Name = strings.TrimSpace(m[1])
		}
		if m := reNxcDomain.FindStringSubmatch(line); m != nil {
			info.Domain = strings.TrimSpace(m[1])
		}
		if m := reNxcOS.FindStringSubmatch(line); m != nil {
			info.OS = strings.TrimSpace(m[1])
		}

		if info.Name != "" {
			return info
		}
	}
	return nil
}

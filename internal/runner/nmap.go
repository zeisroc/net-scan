package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NmapRunner holds configuration for executing nmap.
type NmapRunner struct {
	OutputDir string // directory to save XML files
	MinRate   int
	Proxy     string // SOCKS5 host:port via proxychains; empty = no proxy
	Debug     bool   // print the full nmap command before running
	Verbose   bool   // print full nmap output; default prints only discovered-port lines
}

// targetArgs parses the raw --target value and returns the nmap target arguments.
//
// Accepted formats:
//   - Single IP or CIDR:          "10.10.10.1" / "192.168.1.0/24"
//   - Comma-separated list:       "10.0.0.1,10.0.0.2,192.168.1.0/24"
//   - File path (must exist):     "/tmp/targets.txt"  →  -iL /tmp/targets.txt
func targetArgs(raw string) ([]string, string, error) {
	// Check if it's an existing file.
	if info, err := os.Stat(raw); err == nil && !info.IsDir() {
		label := filepath.Base(raw)
		return []string{"-iL", raw}, label, nil
	}

	// Comma-separated list → split into individual nmap target args.
	if strings.Contains(raw, ",") {
		targets := []string{}
		for _, t := range strings.Split(raw, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			return nil, "", fmt.Errorf("no valid targets in %q", raw)
		}
		label := strings.NewReplacer("/", "_", ":", "_", " ", "_", ",", "+").Replace(raw)
		if len(label) > 40 {
			label = label[:40]
		}
		return targets, label, nil
	}

	// Single IP or CIDR.
	label := strings.NewReplacer("/", "_", ":", "_").Replace(raw)
	return []string{raw}, label, nil
}

// RunAllPorts runs phase 1: nmap -p- to discover all open ports.
//
// Output behaviour:
//   - default:  only "Discovered open port" lines are printed
//   - --verbose: full nmap output is printed
//
// Returns the path to the saved XML file.
func (r *NmapRunner) RunAllPorts(target string) (string, error) {
	tArgs, label, err := targetArgs(target)
	if err != nil {
		return "", err
	}
	xmlPath := r.xmlPathFromLabel(label, "phase1")
	nmapArgs := append([]string{"-p-", fmt.Sprintf("--min-rate=%d", r.MinRate), "-oX", xmlPath}, tArgs...)
	return xmlPath, r.run(r.buildArgs(nmapArgs), true)
}

// RunServiceDetection runs phase 2: nmap -sV -sC on specific ports.
//
// Output behaviour:
//   - default:  silent
//   - --verbose: full nmap output is printed
//
// Returns the path to the saved XML file.
func (r *NmapRunner) RunServiceDetection(target, ports string) (string, error) {
	tArgs, label, err := targetArgs(target)
	if err != nil {
		return "", err
	}
	xmlPath := r.xmlPathFromLabel(label, "phase2")
	nmapArgs := append([]string{"-p", ports, "-sV", "-sC", "-oX", xmlPath}, tArgs...)
	return xmlPath, r.run(r.buildArgs(nmapArgs), false)
}

// buildArgs assembles the full command: [proxychains -q] sudo nmap <nmapArgs...>
func (r *NmapRunner) buildArgs(nmapArgs []string) []string {
	var args []string
	if r.Proxy != "" {
		args = append(args, "proxychains", "-q")
	}
	args = append(args, "sudo", "nmap")
	args = append(args, nmapArgs...)
	return args
}

// run executes the assembled command.
//
// isPhase1 controls output when Verbose is false:
//   - true  → filter stdout to "Discovered open port" lines only
//   - false → discard stdout (silent)
//
// When Verbose is true, full stdout is always printed regardless of isPhase1.
func (r *NmapRunner) run(args []string, isPhase1 bool) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	if r.Debug {
		fmt.Fprintf(os.Stderr, "\033[33m[debug] %s\033[0m\n", strings.Join(args, " "))
	}
	cmd.Stdin = os.Stdin   // allow sudo password prompt
	cmd.Stderr = os.Stderr // nmap progress lines

	switch {
	case r.Verbose:
		// Full output for both phases.
		cmd.Stdout = os.Stdout
		return runCmd(cmd)

	case isPhase1:
		// Filter: only print "Discovered open port" lines.
		pr, pw := io.Pipe()
		cmd.Stdout = pw
		done := make(chan error, 1)
		go func() {
			done <- filterDiscovered(pr)
		}()
		if err := cmd.Run(); err != nil {
			pw.Close()
			return fmt.Errorf("nmap: %w", err)
		}
		pw.Close()
		return <-done

	default:
		// Phase 2, non-verbose: silent.
		cmd.Stdout = io.Discard
		return runCmd(cmd)
	}
}

func runCmd(cmd *exec.Cmd) error {
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap: %w", err)
	}
	return nil
}

// filterDiscovered reads nmap stdout and prints only "Discovered open port" lines.
func filterDiscovered(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Discovered open port") {
			fmt.Println(line)
		}
	}
	return scanner.Err()
}

// xmlPathFromLabel returns a timestamped XML path using a sanitised label.
func (r *NmapRunner) xmlPathFromLabel(label, phase string) string {
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(r.OutputDir, fmt.Sprintf("%s_%s_%s.xml", ts, label, phase))
}


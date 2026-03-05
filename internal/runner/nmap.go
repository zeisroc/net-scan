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
}

// RunAllPorts runs phase 1: nmap -p- to discover all open ports.
// It streams nmap output to stdout in real time.
// Returns the path to the saved XML file.
func (r *NmapRunner) RunAllPorts(target string) (string, error) {
	xmlPath := r.xmlPath(target, "phase1")
	args := r.buildArgs([]string{
		"-p-",
		fmt.Sprintf("--min-rate=%d", r.MinRate),
		"-oX", xmlPath,
		target,
	})
	return xmlPath, r.run(args, true)
}

// RunServiceDetection runs phase 2: nmap -sV -sC on specific ports.
// Returns the path to the saved XML file.
func (r *NmapRunner) RunServiceDetection(target, ports string) (string, error) {
	xmlPath := r.xmlPath(target, "phase2")
	args := r.buildArgs([]string{
		"-p", ports,
		"-sV", "-sC",
		"-oX", xmlPath,
		target,
	})
	return xmlPath, r.run(args, false)
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

// run executes the assembled command. When stream=true it pipes stdout directly
// to os.Stdout so the user sees live output; otherwise output is suppressed.
func (r *NmapRunner) run(args []string, stream bool) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin   // allow sudo password prompt
	cmd.Stderr = os.Stderr // nmap status lines go to stderr

	if stream {
		pr, pw := io.Pipe()
		cmd.Stdout = pw

		done := make(chan error, 1)
		go func() {
			done <- streamPorts(pr)
		}()

		if err := cmd.Run(); err != nil {
			pw.Close()
			return fmt.Errorf("nmap: %w", err)
		}
		pw.Close()
		return <-done
	}

	// Non-streaming: just print the live nmap output as-is.
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap: %w", err)
	}
	return nil
}

// streamPorts reads nmap stdout line by line. When a new open port is seen
// it prints a highlighted IP:PORT line immediately.
func streamPorts(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line) // echo raw output

		// Detect lines like: "Discovered open port 22/tcp on 192.168.1.1"
		if strings.Contains(line, "Discovered open port") {
			parts := strings.Fields(line)
			// parts[3] = port/proto, parts[5] = ip
			if len(parts) >= 6 {
				portProto := parts[3]
				ip := parts[5]
				portNum := strings.Split(portProto, "/")[0]
				fmt.Printf("\033[32m[+] OPEN  %s:%s\033[0m\n", ip, portNum)
			}
		}
	}
	return scanner.Err()
}

// xmlPath returns a timestamped XML path for a given target and phase.
func (r *NmapRunner) xmlPath(target, phase string) string {
	ts := time.Now().Format("20060102_150405")
	safe := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(target)
	return filepath.Join(r.OutputDir, fmt.Sprintf("%s_%s_%s.xml", ts, safe, phase))
}

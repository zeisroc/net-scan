package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Placeholders replaced at runtime inside nmap command templates.
const (
	PlaceholderTarget = "{{TARGET}}" // resolved scan target (IP, CIDR, or -iL /path)
	PlaceholderOutput = "{{OUTPUT}}" // absolute path to the XML output file (mandatory)
	PlaceholderPorts  = "{{PORTS}}"  // comma-separated open TCP port numbers
	PlaceholderRate   = "{{RATE}}"   // value of the --threads flag
)

// Default nmap command templates.
const (
	DefaultPhase1  = "nmap -p- -v --min-rate={{RATE}} -oX {{OUTPUT}} {{TARGET}}"
	DefaultPhase2  = "nmap -p {{PORTS}} -sV -sC -oX {{OUTPUT}} {{TARGET}}"
	DefaultVersion = "nmap -sV -p {{PORTS}} -oX {{OUTPUT}} {{TARGET}}"
)

// ScanTemplates holds the nmap command template for each scan phase.
type ScanTemplates struct {
	Phase1  string `yaml:"phase1"`
	Phase2  string `yaml:"phase2"`
	Version string `yaml:"version"`
}

// Config is the top-level configuration structure.
type Config struct {
	Scan             ScanTemplates `yaml:"scan"`
	InterestingPorts []int         `yaml:"interesting_ports"`
}

// defaultInterestingPorts is the built-in list of management / high-value ports.
var defaultInterestingPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	445,   // SMB
	1433,  // MSSQL
	1521,  // Oracle DB
	3306,  // MySQL / MariaDB
	3389,  // RDP
	5432,  // PostgreSQL
	5985,  // WinRM (HTTP)
	5986,  // WinRM (HTTPS)
	6379,  // Redis
	27017, // MongoDB
}

// Defaults returns a Config pre-filled with the built-in nmap templates.
func Defaults() *Config {
	ports := make([]int, len(defaultInterestingPorts))
	copy(ports, defaultInterestingPorts)
	return &Config{
		Scan: ScanTemplates{
			Phase1:  DefaultPhase1,
			Phase2:  DefaultPhase2,
			Version: DefaultVersion,
		},
		InterestingPorts: ports,
	}
}

// Load reads the config from path. If the file does not exist it is created
// with the default templates and those defaults are returned.
// Missing keys in an existing file fall back to the built-in defaults.
func Load(path string) (*Config, error) {
	expanded, err := expandPath(path)
	if err != nil {
		return nil, fmt.Errorf("expand config path: %w", err)
	}

	if _, err := os.Stat(expanded); errors.Is(err, os.ErrNotExist) {
		cfg := Defaults()
		if writeErr := cfg.writeFile(expanded); writeErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Could not write default config to %s: %v\n", expanded, writeErr)
		} else {
			fmt.Fprintf(os.Stderr, "[i] Created default config at %s\n", expanded)
		}
		return cfg, nil
	}

	data, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", expanded, err)
	}

	// Seed with defaults so keys absent from the file keep working values.
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", expanded, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", expanded, err)
	}

	return cfg, nil
}

// Validate checks that every template contains its required placeholders.
// {{OUTPUT}} is mandatory in all templates — it is what feeds the XML parser.
func (c *Config) Validate() error {
	type rule struct {
		key         string
		tmpl        string
		required    []string
	}
	rules := []rule{
		{"scan.phase1", c.Scan.Phase1, []string{PlaceholderOutput, PlaceholderTarget}},
		{"scan.phase2", c.Scan.Phase2, []string{PlaceholderOutput, PlaceholderPorts, PlaceholderTarget}},
		{"scan.version", c.Scan.Version, []string{PlaceholderOutput, PlaceholderPorts, PlaceholderTarget}},
	}
	for _, r := range rules {
		for _, p := range r.required {
			if !strings.Contains(r.tmpl, p) {
				return fmt.Errorf("%s is missing required placeholder %s", r.key, p)
			}
		}
	}
	return nil
}

// writeFile writes the annotated default config YAML to path, creating
// parent directories as needed.
func (c *Config) writeFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	return os.WriteFile(path, []byte(defaultConfigYAML), 0o644)
}

func expandPath(path string) (string, error) {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}

// defaultConfigYAML is the annotated template written to disk on first run.
const defaultConfigYAML = `# net-scan — configuration
# Location: ~/.pwnbox/net-scan.yaml

# ── nmap command templates ────────────────────────────────────────────────────
#
# Edit these templates to customise the exact nmap flags used in each phase.
#
# Placeholders (substituted at runtime — do NOT remove the mandatory ones):
#   {{TARGET}}   resolved scan target: single IP, CIDR, or "-iL /path/to/file"
#   {{OUTPUT}}   *** MANDATORY *** absolute path for the XML output file
#                Removing this placeholder will cause a startup error.
#   {{PORTS}}    comma-separated open TCP ports (Phase 2 and version scan only)
#   {{RATE}}     value of the --threads flag (default: 5000)
#
# Notes:
#   • Leading "nmap" is optional — it is stripped and re-added with sudo.
#   • When --proxychains is set, "proxychains -q [-f config]" is prepended
#     automatically and -sT is injected if not already present in the template.
#   • -oX {{OUTPUT}} must be kept in every template or results cannot be parsed.

scan:
  phase1:  "nmap -p- -v --min-rate={{RATE}} -oX {{OUTPUT}} {{TARGET}}"
  phase2:  "nmap -p {{PORTS}} -sV -sC -oX {{OUTPUT}} {{TARGET}}"
  version: "nmap -sV -p {{PORTS}} -oX {{OUTPUT}} {{TARGET}}"

# ── Interesting ports ─────────────────────────────────────────────────────────
#
# Ports in this list are highlighted in red in "net-scan list" output.
# Add or remove entries to match your engagement scope.

interesting_ports:
  - 21      # FTP
  - 22      # SSH
  - 23      # Telnet
  - 445     # SMB
  - 1433    # MSSQL
  - 1521    # Oracle DB
  - 3306    # MySQL / MariaDB
  - 3389    # RDP
  - 5432    # PostgreSQL
  - 5985    # WinRM (HTTP)
  - 5986    # WinRM (HTTPS)
  - 6379    # Redis
  - 27017   # MongoDB
`

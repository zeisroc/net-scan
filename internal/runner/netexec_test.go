package runner

import (
"testing"
)

func TestParseNxcSMBOutput(t *testing.T) {
line := "SMB         192.168.143.200 445    WEB04            [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB04) (domain:cowmotors.com) (signing:False) (SMBv1:False)\n"
info := parseNxcSMBOutput(line)
if info == nil {
t.Fatal("expected non-nil SMBInfo")
}
if info.Name != "WEB04" {
t.Errorf("Name: got %q, want %q", info.Name, "WEB04")
}
if info.Domain != "cowmotors.com" {
t.Errorf("Domain: got %q, want %q", info.Domain, "cowmotors.com")
}
if info.OS == "" {
t.Error("OS should not be empty")
}
t.Logf("OS: %s", info.OS)
}

func TestParseNxcSMBOutput_NoMatch(t *testing.T) {
if got := parseNxcSMBOutput(""); got != nil {
t.Errorf("expected nil for empty input, got %+v", got)
}
if got := parseNxcSMBOutput("SMB  10.0.0.1  445  HOST  [-] Access denied\n"); got != nil {
t.Errorf("expected nil when no [*] line, got %+v", got)
}
}

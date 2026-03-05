package models

import "time"

// Host represents a scanned network host.
type Host struct {
	ID        int64
	IP        string
	Hostname  string
	OSGuess   string
	Source    string // comma-separated: 'nmap', 'sharpscan', 'WEB05', etc.
	Project   string
	CreatedAt time.Time
	UpdatedAt time.Time
	Ports     []OpenPort
}

// OpenPort represents an open port on a host.
type OpenPort struct {
	ID        int64
	HostID    int64
	Port      int
	Protocol  string // tcp / udp
	State     string // open / filtered
	Service   string
	Version   string
	Source    string // comma-separated source names
	ScannedAt time.Time
}

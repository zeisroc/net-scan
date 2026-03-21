package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/pwnbox/net_scan/internal/models"
)

// nmap XML structures
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status      nmapStatus      `xml:"status"`
	Addresses   []nmapAddress   `xml:"address"`
	Hostnames   nmapHostnames   `xml:"hostnames"`
	Ports       nmapPorts       `xml:"ports"`
	OS          nmapOS          `xml:"os"`
	HostScripts nmapHostScripts `xml:"hostscript"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Names []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name string `xml:"name,attr"`
}

type nmapHostScripts struct {
	Scripts []nmapScript `xml:"script"`
}

type nmapScript struct {
	ID    string     `xml:"id,attr"`
	Elems []nmapElem `xml:"elem"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// ParseNmapXMLFile parses an nmap XML file and returns hosts with open ports.
func ParseNmapXMLFile(path, source string) ([]models.Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open nmap xml %s: %w", path, err)
	}
	defer f.Close()
	return ParseNmapXML(f, source)
}

// ParseNmapXML parses nmap XML from a reader.
func ParseNmapXML(r io.Reader, source string) ([]models.Host, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("decode nmap xml: %w", err)
	}

	var hosts []models.Host
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}

		host := models.Host{Source: source}

		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				host.IP = addr.Addr
				break
			}
		}
		if host.IP == "" {
			continue
		}

		for _, hn := range h.Hostnames.Names {
			if hn.Type == "PTR" || host.Hostname == "" {
				host.Hostname = hn.Name
			}
		}

		if len(h.OS.Matches) > 0 {
			host.OSGuess = h.OS.Matches[0].Name
		}

		// smb-os-discovery script (runs via -sC when port 445 is open) leaks the
		// NetBIOS computer name and OS string directly from the Windows machine.
		// This is more reliable than reverse DNS for Windows hosts in AD environments.
		for _, script := range h.HostScripts.Scripts {
			if script.ID != "smb-os-discovery" {
				continue
			}
			elems := make(map[string]string, len(script.Elems))
			for _, e := range script.Elems {
				elems[e.Key] = e.Value
			}
			// Prefer short computer name (e.g. "DC01"); fall back to FQDN.
			if name := elems["server"]; name != "" {
				host.Hostname = name
			} else if fqdn := elems["fqdn"]; fqdn != "" && host.Hostname == "" {
				host.Hostname = fqdn
			}
			// Use SMB OS string when nmap's -O detection produced nothing.
			if host.OSGuess == "" {
				if osStr := elems["os"]; osStr != "" {
					host.OSGuess = osStr
				}
			}
		}

		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			portNum, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}

			version := p.Service.Product
			if p.Service.Version != "" {
				version += " " + p.Service.Version
			}
			if p.Service.ExtraInfo != "" {
				version += " (" + p.Service.ExtraInfo + ")"
			}

			host.Ports = append(host.Ports, models.OpenPort{
				Port:     portNum,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Version:  version,
				Source:   source,
			})
		}

		hosts = append(hosts, host)
	}
	return hosts, nil
}

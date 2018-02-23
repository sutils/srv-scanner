package sscanner

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

var tcpPortRegex = regexp.MustCompile("[0-9]+/tcp\\s+[^\\s]*")
var tcpSplitRegex = regexp.MustCompile("/tcp\\s+")
var udpPortRegex = regexp.MustCompile("[0-9]+/udp\\s+[^\\s]*")
var udpSplitRegex = regexp.MustCompile("/udp\\s+")

//NMAP is tool for scan the services by nmap tool
type NMAP struct {
	Bin      string
	Ranges   [2]int
	Host     string
	Protocol string
	Output   string
	Cmd      *exec.Cmd
}

//NewNMAP is creator for NMAP by target host and scan protocol(tcp/udp).
func NewNMAP(host, protocol string) *NMAP {
	return &NMAP{
		Bin:      "nmap",
		Ranges:   [2]int{0, 65535},
		Host:     host,
		Protocol: protocol,
	}
}

//Scan will scan all port by nmap tools and return port map to status.
//see nmap for detail.
func (n *NMAP) Scan() (ports map[int]string, err error) {
	switch n.Protocol {
	case "udp":
		fallthrough
	case "UDP":
		ports, err = n.scanUDP()
	default:
		ports, err = n.scanTCP()
	}
	return
}

func (n *NMAP) scanTCP() (ports map[int]string, err error) {
	ranges := fmt.Sprintf("%v-%v", n.Ranges[0], n.Ranges[1])
	n.Cmd = exec.Command(n.Bin, "-sS", "-O", "-p", ranges, n.Host)
	// cmds := fmt.Sprintf("%v -sS -p %v-%v %v", n.Bin, n.Ranges[0], n.Ranges[1], n.Host)
	// n.Cmd = exec.Command("bash", "-c", cmds)
	output, err := n.Cmd.CombinedOutput()
	n.Output = string(output)
	if err != nil {
		return
	}
	ports = map[int]string{}
	services := tcpPortRegex.FindAllString(n.Output, -1)
	var port int
	for _, service := range services {
		parts := tcpSplitRegex.Split(service, 2)
		port, err = strconv.Atoi(parts[0])
		if err != nil {
			return
		}
		ports[port] = parts[1]
	}
	return
}

func (n *NMAP) scanUDP() (ports map[int]string, err error) {
	ranges := fmt.Sprintf("%v-%v", n.Ranges[0], n.Ranges[1])
	n.Cmd = exec.Command(n.Bin, "-sU", "--min-rate", "5000", "-O", "-p", ranges, n.Host)
	// cmds := fmt.Sprintf("%v -sU --min-rate 5000 -p %v-%v %v", n.Bin, n.Ranges[0], n.Ranges[1], n.Host)
	// n.Cmd = exec.Command("bash", "-c", cmds)
	output, err := n.Cmd.CombinedOutput()
	if err != nil {
		return
	}
	ports = map[int]string{}
	services := udpPortRegex.FindAllString(string(output), -1)
	var port int
	for _, service := range services {
		parts := udpSplitRegex.Split(service, 2)
		port, err = strconv.Atoi(parts[0])
		if err != nil {
			return
		}
		ports[port] = parts[1]
	}
	return
}

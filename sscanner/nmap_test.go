package sscanner

import (
	"fmt"
	"testing"
)

func TestNMAP(t *testing.T) {
	tcp := NewNMAP("loc.m", "tcp")
	tcp.Bin = "/usr/local/bin/nmap"
	tcp.Ranges[0], tcp.Ranges[1] = 70, 81
	ports, err := tcp.Scan()
	if err != nil {
		t.Error(tcp.Output)
		return
	}
	fmt.Println(tcp.Output)
	fmt.Println(ports)
	//
	udp := NewNMAP("loc.m", "udp")
	udp.Bin = "/usr/local/bin/nmap"
	udp.Ranges[0], udp.Ranges[1] = 70, 81
	ports, err = udp.Scan()
	if err != nil {
		t.Error(udp.Output)
		return
	}
	fmt.Println(udp.Output)
	fmt.Println(ports)
}

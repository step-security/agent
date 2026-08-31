//go:build linux
// +build linux

package main

import (
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

func Test_addAuditRules(t *testing.T) {
	err := AddAuditRules(nil)
	if err != nil {
		t.Errorf("Error not expected %v", err)
	}

	ipt, err := iptables.New()

	if err != nil {
		t.Errorf("Error not expected creating iptables %v", err)
	}

	ipt.ClearChain("filter", "OUTPUT")
	ipt.ClearChain("filter", "DOCKER-USER")

	endpoints := []ipAddressEndpoint{}
	endpoints = append(endpoints, ipAddressEndpoint{ipAddress: "1.1.1.1", port: "443"})

	err = addBlockRulesForGitHubHostedRunner(nil, endpoints)
	if err != nil {
		t.Errorf("Error not expected %v", err)
	}

	ipt, err = iptables.New()

	if err != nil {
		t.Errorf("Error not expected creating iptables %v", err)
	}

	assertAcceptRule(t, ipt, outputChain, outbound, defaultInterface, tcp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, outputChain, outbound, defaultInterface, udp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, dockerUserChain, inbound, dockerInterface, tcp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, dockerUserChain, inbound, dockerInterface, udp, "1.1.1.1", "443")

	ipt.ClearChain("filter", "OUTPUT")
	ipt.ClearChain("filter", "DOCKER-USER")
}

func Test_InsertAllowRule_AddsTCPAndUDP(t *testing.T) {
	ipt, err := iptables.New()
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}

	_ = ipt.NewChain(filterTable, dockerUserChain)
	_ = ipt.ClearChain(filterTable, outputChain)
	_ = ipt.ClearChain(filterTable, dockerUserChain)

	t.Cleanup(func() {
		_ = ipt.ClearChain(filterTable, outputChain)
		_ = ipt.ClearChain(filterTable, dockerUserChain)
	})

	err = InsertAllowRule(&Firewall{IPTables: ipt}, nil, "1.1.1.1", "443")
	if err != nil {
		t.Fatalf("InsertAllowRule: %v", err)
	}

	assertAcceptRule(t, ipt, outputChain, outbound, defaultInterface, tcp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, outputChain, outbound, defaultInterface, udp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, dockerUserChain, inbound, dockerInterface, tcp, "1.1.1.1", "443")
	assertAcceptRule(t, ipt, dockerUserChain, inbound, dockerInterface, udp, "1.1.1.1", "443")
}

func assertAcceptRule(t *testing.T, ipt *iptables.IPTables, chain, direction, iface, proto, ip, port string) {
	t.Helper()
	exists, err := ipt.Exists(filterTable, chain, direction, iface, protocol, proto,
		destination, ip, destinationPort, port, target, accept)
	if err != nil {
		t.Fatalf("Exists(%s %s %s:%s): %v", chain, proto, ip, port, err)
	}
	if !exists {
		t.Fatalf("missing ACCEPT rule: chain=%s proto=%s dest=%s:%s iface=%s", chain, proto, ip, port, iface)
	}
}

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

	ipt.ClearChain("filter", "OUTPUT")
	ipt.ClearChain("filter", "DOCKER-USER")
}

func Test_convertIpAddressToCIDR(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "pass", args: args{ip: "100.200.300.400"}, want: "100.200.300.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertIpAddressToCIDR(tt.args.ip); got != tt.want {
				t.Errorf("convertIpAddressToCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

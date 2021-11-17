//go:build linux
// +build linux

package main

import (
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

func Test_addAuditRules(t *testing.T) {
	err := addAuditRules(nil)
	if err != nil {
		t.Errorf("Error not expected %v", err)
	}

	ipt, err := iptables.New()

	if err != nil {
		t.Errorf("Error not expected creating iptables %v", err)
	}

	ipt.ClearChain("filter", "OUTPUT")
	ipt.ClearChain("filter", "DOCKER-USER")
}

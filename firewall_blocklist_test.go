package main

import "testing"

type recorderIPTables struct {
	appended [][]string
	inserted [][]string
}

func (m *recorderIPTables) Append(table, chain string, rulespec ...string) error {
	record := append([]string{table, chain}, rulespec...)
	m.appended = append(m.appended, record)
	return nil
}

func (m *recorderIPTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	return false, nil
}

func (m *recorderIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	record := append([]string{table, chain}, rulespec...)
	m.inserted = append(m.inserted, record)
	return nil
}

func (m *recorderIPTables) ClearChain(table, chain string) error {
	return nil
}

func insertedRuleTarget(record []string) string {
	for i := 0; i < len(record)-1; i++ {
		if record[i] == target {
			return record[i+1]
		}
	}

	return ""
}

func ruleProtocol(record []string) string {
	for i := 0; i < len(record)-1; i++ {
		if record[i] == protocol {
			return record[i+1]
		}
	}

	return ""
}

func TestAddGlobalBlockRules(t *testing.T) {
	ipt := &recorderIPTables{}
	blocklist := NewGlobalBlocklist(&GlobalBlocklistResponse{
		IPAddresses: []CompromisedEndpoint{{Endpoint: "1.2.3.4", Reason: "compromised"}},
	})

	err := AddGlobalBlockRules(&Firewall{ipt}, blocklist)
	if err != nil {
		t.Fatalf("AddGlobalBlockRules() error = %v", err)
	}

	if len(ipt.inserted) != 6 {
		t.Fatalf("expected 6 inserted rules, got %d", len(ipt.inserted))
	}

	expectedTargets := []string{nflogTarget, nflogTarget, reject, nflogTarget, nflogTarget, reject}
	for i, targetName := range expectedTargets {
		record := ipt.inserted[i]
		if insertedRuleTarget(record) != targetName {
			t.Fatalf("expected inserted rule %d target %s, got %#v", i, targetName, record)
		}
	}
}

func TestAddGlobalBlockRules_WithNilBlocklist(t *testing.T) {
	ipt := &recorderIPTables{}
	err := AddGlobalBlockRules(&Firewall{ipt}, nil)
	if err != nil {
		t.Fatalf("AddGlobalBlockRules() error = %v", err)
	}

	if len(ipt.inserted) != 0 {
		t.Fatalf("expected no inserted rules, got %d", len(ipt.inserted))
	}
}

func TestInsertAllowRule_SkipsGlobalBlocklistedIP(t *testing.T) {
	blocklist := NewGlobalBlocklist(&GlobalBlocklistResponse{
		IPAddresses: []CompromisedEndpoint{{Endpoint: "1.2.3.4", Reason: "compromised"}},
	})

	ipt := &recorderIPTables{}

	err := InsertAllowRule(&Firewall{ipt}, blocklist, "1.2.3.4", "443")
	if err != nil {
		t.Fatalf("InsertAllowRule() error = %v", err)
	}

	if len(ipt.inserted) != 0 {
		t.Fatalf("expected no inserted allow rules, got %d", len(ipt.inserted))
	}
}

func TestInsertAllowRule_AllowsWhenBlocklistIsNil(t *testing.T) {
	ipt := &recorderIPTables{}

	err := InsertAllowRule(&Firewall{ipt}, nil, "1.2.3.4", "443")
	if err != nil {
		t.Fatalf("InsertAllowRule() error = %v", err)
	}

	// TCP + UDP for OUTPUT and DOCKER-USER
	if len(ipt.inserted) != 4 {
		t.Fatalf("expected four inserted allow rules (tcp+udp x 2 chains), got %d", len(ipt.inserted))
	}

	expectedProtocols := []string{tcp, tcp, udp, udp}
	expectedChains := []string{outputChain, dockerUserChain, outputChain, dockerUserChain}
	for i, record := range ipt.inserted {
		if insertedRuleTarget(record) != accept {
			t.Fatalf("expected inserted rule %d target %s, got %#v", i, accept, record)
		}
		if ruleProtocol(record) != expectedProtocols[i] {
			t.Fatalf("expected inserted rule %d protocol %s, got %#v", i, expectedProtocols[i], record)
		}
		if record[1] != expectedChains[i] {
			t.Fatalf("expected inserted rule %d chain %s, got %#v", i, expectedChains[i], record)
		}
	}
}

func TestAddBlockRules_AllowsTCPAndUDPForEndpoints(t *testing.T) {
	ipt := &recorderIPTables{}
	endpoints := []ipAddressEndpoint{{ipAddress: "1.1.1.1", port: "443"}}

	err := addBlockRules(&Firewall{ipt}, endpoints, outputChain, defaultInterface, outbound)
	if err != nil {
		t.Fatalf("addBlockRules() error = %v", err)
	}

	var tcpAllow, udpAllow bool
	for _, record := range ipt.appended {
		if insertedRuleTarget(record) != accept {
			continue
		}
		if record[1] != outputChain {
			continue
		}
		dest := ""
		dport := ""
		for i := 0; i < len(record)-1; i++ {
			if record[i] == destination {
				dest = record[i+1]
			}
			if record[i] == destinationPort {
				dport = record[i+1]
			}
		}
		if dest != "1.1.1.1" || dport != "443" {
			continue
		}
		switch ruleProtocol(record) {
		case tcp:
			tcpAllow = true
		case udp:
			udpAllow = true
		}
	}

	if !tcpAllow {
		t.Fatal("expected TCP ACCEPT rule for allowed endpoint")
	}
	if !udpAllow {
		t.Fatal("expected UDP ACCEPT rule for allowed endpoint")
	}
}

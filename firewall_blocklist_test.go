package main

import "testing"

type recorderIPTables struct {
	inserted [][]string
}

func (m *recorderIPTables) Append(table, chain string, rulespec ...string) error {
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

func TestAddGlobalBlockRules(t *testing.T) {
	ipt := &recorderIPTables{}
	blocklist := NewGlobalBlocklist(&GlobalBlocklistResponse{
		IPAddresses: []CompromisedEndpoint{{Endpoint: "1.2.3.4", Reason: "compromised"}},
	})

	err := AddGlobalBlockRules(&Firewall{ipt}, blocklist)
	if err != nil {
		t.Fatalf("AddGlobalBlockRules() error = %v", err)
	}

	if len(ipt.inserted) != 4 {
		t.Fatalf("expected 4 inserted rules, got %d", len(ipt.inserted))
	}

	expectedTargets := []string{nflogTarget, reject, nflogTarget, reject}
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

	if len(ipt.inserted) != 2 {
		t.Fatalf("expected two inserted allow rules, got %d", len(ipt.inserted))
	}

	for i, record := range ipt.inserted {
		if insertedRuleTarget(record) != accept {
			t.Fatalf("expected inserted rule %d target %s, got %#v", i, accept, record)
		}
	}
}

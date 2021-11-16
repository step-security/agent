package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/jarcoal/httpmock"
)

type mockDNSServer struct {
	DNSServer
}

type mockDNSServerWithError struct {
	DNSServer
}

func (m *mockDNSServer) ListenAndServe() error {
	return nil
}

func (m *mockDNSServerWithError) ListenAndServe() error {

	return fmt.Errorf("error")
}

type MockIPTables struct {
	IPTables
}

func (m *MockIPTables) Append(table, chain string, rulespec ...string) error {
	return nil
}

func (m *MockIPTables) ClearChain(table, chain string) error {
	return nil
}

type MockAgentNflogger struct {
	AgentNflogger
}

func (m *MockAgentNflogger) Open(config *nflog.Config) (AgentNfLog, error) {
	return AgentNfLog{&MockNfLogger{}}, nil
}

type MockAgentNfloggerWithErr struct {
	AgentNflogger
}

func (m *MockAgentNfloggerWithErr) Open(config *nflog.Config) (AgentNfLog, error) {
	return AgentNfLog{&MockNfLogger{}}, fmt.Errorf("failed to open nflog")
}

type MockNfLogger struct {
	NfLogger
}

func (m *MockNfLogger) Close() error {
	return nil
}
func (m *MockNfLogger) Register(ctx context.Context, fn nflog.HookFunc) error {
	return nil
}

type MockCommand struct {
	Command
}

type MockCommandWithError struct {
	Command
}

func (m *MockCommand) Run() error {
	return nil
}

func (m *MockCommandWithError) Run() error {
	return fmt.Errorf("failed to run command")
}

func TestRun(t *testing.T) {

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(2*time.Second, cancel)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/owner/repo/actions/runs/1287185438/monitor", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	err := Run(ctx, "./testfiles/agent.json",
		&mockDNSServer{}, &mockDNSServer{}, &Firewall{&MockIPTables{}},
		&MockAgentNflogger{}, &MockCommand{}, createTempFileWithContents(""), createTempFileWithContents("{}"), nil)

	if err != nil {
		fmt.Printf("err: %v\n", err)
		t.Fail()
	}
}

func TestRunWithDNSFailure(t *testing.T) {

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(5*time.Second, cancel) // this should not be used, it should error out earlier

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/owner/repo/actions/runs/1287185438/monitor", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	err := Run(ctx, "./testfiles/agent.json",
		&mockDNSServer{}, &mockDNSServerWithError{}, &Firewall{&MockIPTables{}},
		&MockAgentNflogger{}, &MockCommand{}, createTempFileWithContents(""), createTempFileWithContents("{}"), nil)

	// if 2 seconds pass
	if err == nil {
		t.Fail()
	}

}

func TestRunWithCMDFailure(t *testing.T) {

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(5*time.Second, cancel) // this should not be used, it should error out earlier

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/owner/repo/actions/runs/1287185438/monitor", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	err := Run(ctx, "./testfiles/agent.json",
		&mockDNSServer{}, &mockDNSServer{}, &Firewall{&MockIPTables{}},
		&MockAgentNflogger{}, &MockCommandWithError{}, createTempFileWithContents(""), createTempFileWithContents("{}"), nil)

	// if 2 seconds pass
	if err == nil {
		t.Fail()
	}

}

/*
func TestRunWithNflogError(t *testing.T) {

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(5*time.Second, cancel) // this should not be used, it should error out earlier

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/owner/repo/actions/runs/1287185438/monitor", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	err := Run(ctx, "./testfiles/agent.json",
		&mockDNSServer{}, &mockDNSServer{}, &Firewall{&MockIPTables{}},
		&MockAgentNfloggerWithErr{}, &MockCommand{}, createTempFileWithContents(""), createTempFileWithContents("{}"), nil)

	// if 2 seconds pass
	if err == nil {
		t.Fail()
	}

}
*/

package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/florianl/go-nflog/v2"
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

func deleteTempFile(path string) {
	os.Remove(path)
}

func getContext(seconds int) context.Context {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(2*time.Second, cancel)

	return ctx
}

func TestRun(t *testing.T) {
	type args struct {
		ctxCancelDuration      int
		configFilePath         string
		hostDNSServer          DNSServer
		dockerDNSServer        DNSServer
		iptables               *Firewall
		nflog                  AgentNflogger
		cmd                    Command
		resolvdConfigPath      string
		dockerDaemonConfigPath string
		ciTestOnly             bool
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: false},
		{name: "success allowed endpoints", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent-allowed-endpoints.json",
			hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: nil, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}"), ciTestOnly: true}, wantErr: false},
		{name: "dns failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServerWithError{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},
		{name: "cmd failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommandWithError{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},
		{name: "nflog failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNfloggerWithErr{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},
	}
	ci := os.Getenv("CI")
	for _, tt := range tests {
		if !tt.args.ciTestOnly || ci == "true" {
			t.Run(tt.name, func(t *testing.T) {
				tempDir := os.TempDir()
				if err := Run(getContext(tt.args.ctxCancelDuration), tt.args.configFilePath, tt.args.hostDNSServer, tt.args.dockerDNSServer,
					tt.args.iptables, tt.args.nflog, tt.args.cmd, tt.args.resolvdConfigPath, tt.args.dockerDaemonConfigPath, tempDir); (err != nil) != tt.wantErr {
					t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				}

				deleteTempFile(path.Join(tempDir, "resolved.conf"))
				deleteTempFile(path.Join(tempDir, "daemon.json"))

				if ci == "true"{
					RevertFirewallChanges(nil)
				}
			})
		}
	}
}

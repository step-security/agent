package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
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

func (m *MockIPTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	return false, nil
}

func (m *MockIPTables) Insert(table, chain string, post int, rulespec ...string) error {
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

func deleteTempFile(path string) {
	os.Remove(path)
}

func getContext(seconds int) context.Context {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(time.Duration(seconds)*time.Second, cancel)

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

	httpmock.Activate()

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=domain1.com.&type=a",
		httpmock.NewStringResponder(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain1.com.","type":1}],"Answer":[{"name":"domain1.com.","type":1,"TTL":30,"data":"67.67.67.67"}]}`))

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=domain2.com.&type=a",
		httpmock.ResponderFromMultipleResponses(
			[]*http.Response{
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain2.com.","type":1}],"Answer":[{"name":"domain2.com.","type":1,"TTL":30,"data":"68.68.68.68"}]}`),
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain2.com.","type":1}],"Answer":[{"name":"domain2.com.","type":1,"TTL":30,"data":"68.68.68.68"}]}`),
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain2.com.","type":1}],"Answer":[{"name":"domain2.com.","type":1,"TTL":30,"data":"70.70.70.70"}]}`),
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain2.com.","type":1}],"Answer":[{"name":"domain2.com.","type":1,"TTL":30,"data":"68.68.68.68"}]}`),
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain2.com.","type":1}],"Answer":[{"name":"domain2.com.","type":1,"TTL":30,"data":"70.70.70.70"}]}`),
			},
			t.Log))

	httpmock.RegisterResponder("GET", "https://dns.google/resolve", // no query params to match all other requests
		httpmock.NewStringResponder(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"requesteddomain.com.","type":1}],"Answer":[{"name":"requesteddomain.com.","type":1,"TTL":300,"data":"69.69.69.69"}]}`))

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success egress audit", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: false},

		{name: "success egress blocked", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent-allowed-endpoints.json",
			hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: false},

		// ctx will cancel after 35 seconds
		// DNS refresh will be done after 30 seconds
		{name: "success egress blocked DNS refresh", args: args{ctxCancelDuration: 35, configFilePath: "./testfiles/agent-allowed-endpoints.json",
			hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: false},

		{name: "dns failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServerWithError{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},

		{name: "cmd failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: &MockCommandWithError{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},

		{name: "nflog failure", args: args{ctxCancelDuration: 5, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNfloggerWithErr{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}")}, wantErr: true},

		// CI only tests
		{name: "success monitor process CI Test", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent.json", hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: &Firewall{&MockIPTables{}}, nflog: &MockAgentNflogger{}, cmd: nil, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}"), ciTestOnly: true}, wantErr: false},

		{name: "success allowed endpoints CI Test", args: args{ctxCancelDuration: 2, configFilePath: "./testfiles/agent-allowed-endpoints.json",
			hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: nil, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}"), ciTestOnly: true}, wantErr: false},

		{name: "success allowed endpoints DNS refresh CI Test", args: args{ctxCancelDuration: 60, configFilePath: "./testfiles/agent-allowed-endpoints.json",
			hostDNSServer: &mockDNSServer{}, dockerDNSServer: &mockDNSServer{},
			iptables: nil, nflog: &MockAgentNflogger{}, cmd: &MockCommand{}, resolvdConfigPath: createTempFileWithContents(""),
			dockerDaemonConfigPath: createTempFileWithContents("{}"), ciTestOnly: true}, wantErr: false},
	}
	_, ciTest := os.LookupEnv("CI")
	fmt.Printf("ci-test: %t\n", ciTest)
	for _, tt := range tests {
		if !tt.args.ciTestOnly || ciTest {
			t.Run(tt.name, func(t *testing.T) {
				tempDir := os.TempDir()
				if err := Run(getContext(tt.args.ctxCancelDuration), tt.args.configFilePath, tt.args.hostDNSServer, tt.args.dockerDNSServer,
					tt.args.iptables, tt.args.nflog, tt.args.cmd, tt.args.resolvdConfigPath, tt.args.dockerDaemonConfigPath, tempDir); (err != nil) != tt.wantErr {
					t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				}

				deleteTempFile(path.Join(tempDir, "resolved.conf"))
				deleteTempFile(path.Join(tempDir, "daemon.json"))

				if tt.args.ciTestOnly {
					fmt.Printf("Reverting firewall changes\n")
					RevertFirewallChanges(nil)
				}
			})
		}
	}
}

func Test_writeDone(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "writing to done.json", wantErr: false},
	}
	_, ciTest := os.LookupEnv("CI")
	if ciTest {
		for _, tt := range tests {

			t.Run(tt.name, func(t *testing.T) {
				if err := writeDone(); (err != nil) != tt.wantErr {
					t.Errorf("writeDone() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}

	}
}

func Test_writeStatus(t *testing.T) {
	type args struct {
		message string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "writing status", args: args{message: "this is test status"}, wantErr: false},
	}
	_, ciTest := os.LookupEnv("CI")
	if ciTest {
		for _, tt := range tests {

			t.Run(tt.name, func(t *testing.T) {

				if err := writeStatus(tt.args.message); (err != nil) != tt.wantErr {
					t.Errorf("writeStatus() error = %v, wantErr %v", err, tt.wantErr)
				}

			})
		}
	}
}

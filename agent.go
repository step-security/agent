package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/florianl/go-nflog/v2"
)

const (
	StepSecurityLogCorrelationPrefix = "Step Security Job Correlation ID:"
	EgressPolicyAudit                = "audit"
	EgressPolicyBlock                = "block"
)

type DNSServer interface {
	ListenAndServe() error
}

type Command interface {
	Run() error
}

type AgentNflogger interface {
	Open(config *nflog.Config) (AgentNfLog, error)
}

type AgentNfLog struct {
	NfLogger
}

type NfLogger interface {
	Close() error
	Register(ctx context.Context, fn nflog.HookFunc) error
}

type Firewall struct {
	IPTables IPTables
}

type IPTables interface {
	Append(table, chain string, rulespec ...string) error
	ClearChain(table, chain string) error
}

// Run the agent
// TODO: move all inputs into a struct
func Run(ctx context.Context, configFilePath string, hostDNSServer DNSServer,
	dockerDNSServer DNSServer, iptables *Firewall, nflog AgentNflogger,
	cmd Command, resolvdConfigPath, dockerDaemonConfigPath, tempDir string) error {

	// Passed to each go routine, if anyone fails, the program fails
	errc := make(chan error)

	config := &config{}
	if err := config.init(configFilePath); err != nil {
		writeStatus(fmt.Sprintf("Error reading config file %v", err))
		return err
	}

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: config.APIURL}

	// TODO: pass in an iowriter/ use log library
	WriteLog(fmt.Sprintf("read config %v", config))

	WriteLog(fmt.Sprintf("%s %s", StepSecurityLogCorrelationPrefix, config.CorrelationId))

	// TODO: fix the cache and time
	Cache := InitCache(10 * 60 * 1000000000) // 10 * 60 seconds

	allowedEndpoints := addImplicitEndpoints(config.Endpoints)

	// Start DNS servers and get confirmation
	dnsProxy := DNSProxy{
		Cache:            &Cache,
		CorrelationId:    config.CorrelationId,
		Repo:             config.Repo,
		ApiClient:        apiclient,
		EgressPolicy:     config.EgressPolicy,
		AllowedEndpoints: allowedEndpoints,
	}

	go startDNSServer(dnsProxy, hostDNSServer, errc)
	go startDNSServer(dnsProxy, dockerDNSServer, errc) // this is for the docker bridge

	// start proc mon
	if cmd == nil {
		procMon := &ProcessMonitor{CorrelationId: config.CorrelationId, Repo: config.Repo, ApiClient: apiclient, WorkingDirectory: config.WorkingDirectory}
		go procMon.MonitorProcesses(errc)
		WriteLog("started process monitor")
	}

	dnsConfig := DnsConfig{}

	var ipAddressEndpoints []ipAddressEndpoint

	// hydrate dns cache
	if config.EgressPolicy == EgressPolicyBlock {
		for _, endpoint := range allowedEndpoints {
			// this will cause domain, IP mapping to be cached
			ipAddress, err := dnsProxy.getIPByDomain(endpoint.domainName)
			if err != nil {
				WriteLog(fmt.Sprintf("Error resolving allowed domain %v", err))
				RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
				return err
			}

			// create list of ip address to be added to firewall
			ipAddressEndpoints = append(ipAddressEndpoints, ipAddressEndpoint{ipAddress: ipAddress, port: fmt.Sprintf("%d", endpoint.port)})
		}
	}

	// Change DNS config on host, causes processes to use agent's DNS proxy
	if err := dnsConfig.SetDNSServer(cmd, resolvdConfigPath, tempDir); err != nil {
		WriteLog(fmt.Sprintf("Error setting DNS server %v", err))
		RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
		return err
	}

	WriteLog("updated resolved")

	// Change DNS for docker, causes process in containers to use agent's DNS proxy
	if err := dnsConfig.SetDockerDNSServer(cmd, dockerDaemonConfigPath, tempDir); err != nil {
		WriteLog(fmt.Sprintf("Error setting DNS server for docker %v", err))
		RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
		return err
	}

	WriteLog("set docker config")

	if config.EgressPolicy == EgressPolicyAudit {
		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Allowed",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(nflog, errc) // listens for NFLOG messages

		WriteLog("before audit rules")

		// Add logging to firewall, including NFLOG rules
		if err := AddAuditRules(iptables); err != nil {
			WriteLog(fmt.Sprintf("Error adding firewall rules %v", err))
			RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
			return err
		}

		WriteLog("added audit rules")
	} else if config.EgressPolicy == EgressPolicyBlock {

		WriteLog(fmt.Sprintf("Allowed domains:%v", config.Endpoints))

		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Dropped",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(nflog, errc) // listens for NFLOG messages

		if err := addBlockRulesForGitHubHostedRunner(ipAddressEndpoints); err != nil {
			WriteLog(fmt.Sprintf("Error setting firewall for allowed domains %v", err))
			RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
			return err
		}
	}

	WriteLog("done")

	// Write the status file
	writeStatus("Initialized")

	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-errc:
			WriteLog(fmt.Sprintf("Error in Initialization %v", e))
			RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
			return e

		}
	}
}

func addImplicitEndpoints(endpoints []Endpoint) []Endpoint {
	implicitEndpoints := []Endpoint{
		{domainName: "agent.api.stepsecurity.io", port: 443},               // Should be implicit based on user feedback
		{domainName: "pipelines.actions.githubusercontent.com", port: 443}, // GitHub
		{domainName: "codeload.github.com", port: 443},                     // GitHub
		{domainName: "token.actions.githubusercontent.com", port: 443},     // GitHub
		{domainName: "vstoken.actions.githubusercontent.com", port: 443},   // GitHub
		{domainName: "vstsmms.actions.githubusercontent.com", port: 443},   // GitHub
	}

	return append(endpoints, implicitEndpoints...)
}

func RevertChanges(iptables *Firewall, nflog AgentNflogger,
	cmd Command, resolvdConfigPath, dockerDaemonConfigPath string, dnsConfig DnsConfig) {
	err := RevertFirewallChanges(iptables)
	if err != nil {
		WriteLog(fmt.Sprintf("Error in RevertChanges %v", err))
	}
	err = dnsConfig.RevertDNSServer(cmd, resolvdConfigPath)
	if err != nil {
		WriteLog(fmt.Sprintf("Error in reverting DNS server changes %v", err))
	}
	err = dnsConfig.RevertDockerDNSServer(cmd, dockerDaemonConfigPath)
	if err != nil {
		WriteLog(fmt.Sprintf("Error in reverting docker DNS server changes %v", err))
	}
	WriteLog("Reverted changes")
}

func writeStatus(message string) {
	f, _ := os.OpenFile("/home/agent/agent.status",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString(message)
}

func writeDone() {
	f, _ := os.OpenFile("/home/agent/done.json",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString("done.json")
}

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

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
	Insert(table, chain string, pos int, rulespec ...string) error
	Exists(table, chain string, rulespec ...string) (bool, error)
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
	WriteLog(fmt.Sprintf("read config \n %v", config))
	WriteLog("\n")

	WriteLog(fmt.Sprintf("%s %s", StepSecurityLogCorrelationPrefix, config.CorrelationId))
	WriteLog("\n")

	Cache := InitCache(config.EgressPolicy)

	allowedEndpoints := addImplicitEndpoints(config.Endpoints)

	// Start DNS servers and get confirmation
	dnsProxy := DNSProxy{
		Cache:            &Cache,
		CorrelationId:    config.CorrelationId,
		Repo:             config.Repo,
		ApiClient:        apiclient,
		EgressPolicy:     config.EgressPolicy,
		AllowedEndpoints: allowedEndpoints,
		ReverseIPLookup:  make(map[string]string),
	}

	go startDNSServer(&dnsProxy, hostDNSServer, errc)
	go startDNSServer(&dnsProxy, dockerDNSServer, errc) // this is for the docker bridge

	// start proc mon
	if cmd == nil {
		procMon := &ProcessMonitor{CorrelationId: config.CorrelationId, Repo: config.Repo,
			ApiClient: apiclient, WorkingDirectory: config.WorkingDirectory, DNSProxy: &dnsProxy}
		go procMon.MonitorProcesses(errc)
		WriteLog("started process monitor")
	}

	dnsConfig := DnsConfig{}

	var ipAddressEndpoints []ipAddressEndpoint

	// hydrate dns cache
	if config.EgressPolicy == EgressPolicyBlock {
		for domainName, endpoints := range allowedEndpoints {
			// this will cause domain, IP mapping to be cached
			ipAddress, err := dnsProxy.getIPByDomain(domainName)
			if err != nil {
				WriteLog(fmt.Sprintf("Error resolving allowed domain %v", err))
				RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
				return err
			}
			for _, endpoint := range endpoints {
				// create list of ip address to be added to firewall
				ipAddressEndpoints = append(ipAddressEndpoints, ipAddressEndpoint{ipAddress: ipAddress, port: fmt.Sprintf("%d", endpoint.port)})
			}

		}
	}

	// Change DNS config on host, causes processes to use agent's DNS proxy
	if err := dnsConfig.SetDNSServer(cmd, resolvdConfigPath, tempDir); err != nil {
		WriteLog(fmt.Sprintf("Error setting DNS server %v", err))
		RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
		return err
	}

	WriteLog("\n")
	WriteLog("updated resolved")

	// Change DNS for docker, causes process in containers to use agent's DNS proxy
	if err := dnsConfig.SetDockerDNSServer(cmd, dockerDaemonConfigPath, tempDir); err != nil {
		WriteLog(fmt.Sprintf("Error setting DNS server for docker %v", err))
		RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
		return err
	}

	WriteLog("\n")
	WriteLog("set docker config\n")

	if config.EgressPolicy == EgressPolicyAudit {
		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Allowed",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(ctx, nflog, errc) // listens for NFLOG messages

		WriteLog("before audit rules")

		// Add logging to firewall, including NFLOG rules
		if err := AddAuditRules(iptables); err != nil {
			WriteLog(fmt.Sprintf("Error adding firewall rules %v", err))
			RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
			return err
		}

		WriteLog("added audit rules")
	} else if config.EgressPolicy == EgressPolicyBlock {

		WriteLog("\n")
		WriteLog(fmt.Sprintf("Allowed domains:%v", config.Endpoints))
		WriteLog("\n")

		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Dropped",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(ctx, nflog, errc) // listens for NFLOG messages

		if err := addBlockRulesForGitHubHostedRunner(iptables, ipAddressEndpoints); err != nil {
			WriteLog(fmt.Sprintf("Error setting firewall for allowed domains %v", err))
			RevertChanges(iptables, nflog, cmd, resolvdConfigPath, dockerDaemonConfigPath, dnsConfig)
			return err
		}

		go refreshDNSEntries(ctx, iptables, allowedEndpoints, &dnsProxy)
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

func refreshDNSEntries(ctx context.Context, iptables *Firewall, allowedEndpoints map[string][]Endpoint, dnsProxy *DNSProxy) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				WriteLog("\n")
				WriteLog("Refreshing DNS entries")
				for domainName, endpoints := range allowedEndpoints {
					element, found := dnsProxy.Cache.Get(domainName)
					if found {
						var err error
						var answer *Answer
						// check if DNS TTL is close to expiry
						if time.Now().Unix()+10-element.TimeAdded > int64(element.Value.TTL) {
							// resolve domain name
							answer, err = dnsProxy.ResolveDomain(domainName)
							if err != nil {
								// log and continue
								WriteLog(fmt.Sprintf("domain could not be resolved: %s, %v", domainName, err))
								continue
							}

							for _, endpoint := range endpoints {
								// add endpoint to firewall
								err = InsertAllowRule(iptables, answer.Data, fmt.Sprintf("%d", endpoint.port))
								if err != nil {
									break
								}
							}

							if err != nil {
								// log and continue
								WriteLog(fmt.Sprintf("failed to insert new ipaddress in firewall: %s, %v", domainName, err))
								continue
							}

							// add to cache with new TTL
							dnsProxy.Cache.Set(domainName, answer)

							WriteLog(fmt.Sprintf("domain resolved: %s, ip address: %s, TTL: %d", domainName, answer.Data, answer.TTL))
						}
					}
				}
			}
		}
	}()

}

func addImplicitEndpoints(endpoints map[string][]Endpoint) map[string][]Endpoint {
	implicitEndpoints := []Endpoint{
		{domainName: "agent.api.stepsecurity.io", port: 443},                   // Should be implicit based on user feedback
		{domainName: "pipelines.actions.githubusercontent.com", port: 443},     // GitHub
		{domainName: "artifactcache.actions.githubusercontent.com", port: 443}, // GitHub
		{domainName: "codeload.github.com", port: 443},                         // GitHub
		{domainName: "token.actions.githubusercontent.com", port: 443},         // GitHub
		{domainName: "vstoken.actions.githubusercontent.com", port: 443},       // GitHub
		{domainName: "vstsmms.actions.githubusercontent.com", port: 443},       // GitHub
	}

	for _, endpoint := range implicitEndpoints {
		endpoints[endpoint.domainName] = append(endpoints[endpoint.domainName], endpoint)
	}

	return endpoints
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

func writeStatus(message string) error {
	dir := "/home/agent"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.Mkdir(dir, 0644)
	}
	f, err := os.OpenFile("/home/agent/agent.status",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString(message)

	return nil
}

func writeDone() error {

	dir := "/home/agent"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.Mkdir(dir, 0644)
	}

	f, err := os.OpenFile("/home/agent/done.json",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return err
	}

	defer f.Close()

	f.WriteString("done.json")

	return nil
}

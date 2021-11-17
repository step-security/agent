package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/florianl/go-nflog/v2"
)

const StepSecurityLogCorrelationPrefix = "Step Security Job Correlation ID:"

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
	cmd Command, resolvdConfigPath, dockerDaemonConfigPath string, stdout io.Writer) error {

	// Passed to each go routine, if anyone fails, the program fails
	errc := make(chan error)

	config := &config{}
	if err := config.init(configFilePath); err != nil {
		writeStatus(fmt.Sprintf("Error reading config file %v", err))
		return err
	}

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: config.APIURL}

	// TODO: pass in an iowriter/ use log library
	writeLog(fmt.Sprintf("read config %v", config))

	writeLog(fmt.Sprintf("%s %s", StepSecurityLogCorrelationPrefix, config.CorrelationId))

	// TODO: fix the cache and time
	Cache := InitCache(10 * 60 * 1000000000) // 10 * 60 seconds

	// Start DNS servers and get confirmation
	dnsProxy := DNSProxy{
		Cache:         &Cache,
		CorrelationId: config.CorrelationId,
		Repo:          config.Repo,
		ApiClient:     apiclient,
	}

	go startDNSServer(dnsProxy, hostDNSServer, errc)
	go startDNSServer(dnsProxy, dockerDNSServer, errc) // this is for the docker bridge

	if len(config.Endpoints) == 0 {
		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Allowed",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(nflog, errc) // listens for NFLOG messages
		//writeLog("started net monitor")
		writeLog("before audit rules")

		// Add logging to firewall, including NFLOG rules
		if err := addAuditRules(iptables); err != nil {
			writeLog(fmt.Sprintf("Error adding firewall rules %v", err))
			return err
		}

		writeLog("added audit rules")
	}

	// TODO: If something did not work, revert settings
	if cmd == nil {
		procMon := &ProcessMonitor{CorrelationId: config.CorrelationId, Repo: config.Repo, ApiClient: apiclient, WorkingDirectory: config.WorkingDirectory}
		go procMon.MonitorProcesses(errc)
		writeLog("started p monitor")
	}

	// Change DNS config on host, causes processes to use agent's DNS proxy
	if err := setDNSServer(cmd, resolvdConfigPath); err != nil {
		writeLog(fmt.Sprintf("Error setting DNS server %v", err))
		return err
	}

	writeLog("updated resolved")

	// Change DNS for docker, causes process in containers to use agent's DNS proxy
	if err := setDockerDNSServer(cmd, dockerDaemonConfigPath); err != nil {
		writeLog(fmt.Sprintf("Error setting DNS server for docker %v", err))
		return err
	}

	writeLog("set docker config")

	// If allowed endpoints set, resolve them, and add to firewall
	if len(config.Endpoints) > 0 {
		var ipAddressEndpoints []ipAddressEndpoint

		writeLog(fmt.Sprintf("Allowed domains:%v", config.Endpoints))

		netMonitor := NetworkMonitor{
			CorrelationId: config.CorrelationId,
			Repo:          config.Repo,
			ApiClient:     apiclient,
			Status:        "Dropped",
		}

		// Start network monitor
		go netMonitor.MonitorNetwork(nflog, errc) // listens for NFLOG messages

		for _, endpoint := range config.Endpoints {
			// this will cause domain, IP mapping to be cached
			ipAddress, err := dnsProxy.getIPByDomain(endpoint.domainName)
			if err != nil {
				writeLog(fmt.Sprintf("Error resolving allowed domain %v", err))
				return err
			}

			// create list of ip address to be added to firewall
			ipAddressEndpoints = append(ipAddressEndpoints, ipAddressEndpoint{ipAddress: ipAddress, port: fmt.Sprintf("%d", endpoint.port)})
		}

		if err := addBlockRulesForGitHubHostedRunner(ipAddressEndpoints); err != nil {
			writeLog(fmt.Sprintf("Error setting firewall for allowed domains %v", err))
			return err
		}
	}

	// Ask API to monitor the run
	go apiclient.monitorRun(config.Repo, config.RunId)

	writeLog("called monitor run")

	writeLog("done")

	// Write the status file
	writeStatus("Initialized")

	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-errc:
			writeLog(e.Error())
			return e

		}
	}
}

func writeLog(message string) {
	f, _ := os.OpenFile("/home/agent/agent.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString(fmt.Sprintf("%s:%s\n", time.Now().String(), message))
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

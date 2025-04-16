package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

type config struct {
	Repo                     string
	CorrelationId            string
	RunId                    string
	WorkingDirectory         string
	APIURL                   string
	OneTimeKey               string
	Endpoints                map[string][]Endpoint
	EgressPolicy             string
	DisableTelemetry         bool
	DisableSudo              bool
	DisableSudoAndContainers bool
	DisableFileMonitoring    bool
	Private                  bool
}

type Endpoint struct {
	domainName string
	port       int
}

type configFile struct {
	Repo                     string `json:"repo"`
	CorrelationId            string `json:"correlation_id"`
	RunId                    string `json:"run_id"`
	WorkingDirectory         string `json:"working_directory"`
	APIURL                   string `json:"api_url"`
	OneTimeKey               string `json:"one_time_key"`
	AllowedEndpoints         string `json:"allowed_endpoints"`
	EgressPolicy             string `json:"egress_policy"`
	DisableTelemetry         bool   `json:"disable_telemetry"`
	DisableSudo              bool   `json:"disable_sudo"`
	DisableSudoAndContainers bool   `json:"disable_sudo_and_containers"`
	DisableFileMonitoring    bool   `json:"disable_file_monitoring"`
	Private                  bool   `json:"private"`
}

// init reads the config file for the agent and initializes config settings
func (c *config) init(configFilePath string) error {
	var configFile configFile
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return errors.Wrap(err, "failed to read config file")
	}

	err = json.Unmarshal([]byte(data), &configFile)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal config file")
	}

	c.CorrelationId = configFile.CorrelationId
	c.Repo = configFile.Repo
	c.RunId = configFile.RunId
	c.WorkingDirectory = configFile.WorkingDirectory
	c.APIURL = configFile.APIURL
	c.Endpoints = parseEndpoints(configFile.AllowedEndpoints)
	c.EgressPolicy = configFile.EgressPolicy
	c.DisableTelemetry = configFile.DisableTelemetry
	c.DisableSudo = configFile.DisableSudo
	c.DisableSudoAndContainers = configFile.DisableSudoAndContainers
	c.DisableFileMonitoring = configFile.DisableFileMonitoring
	c.Private = configFile.Private
	c.OneTimeKey = configFile.OneTimeKey
	return nil
}

func parseEndpoints(allowedEndpoints string) map[string][]Endpoint {
	endpoints := make(map[string][]Endpoint)
	endpointsArray := strings.Split(allowedEndpoints, " ")
	for _, endpoint := range endpointsArray {
		if len(endpoint) > 0 {
			endpointParts := strings.Split(endpoint, ":")
			domainName := endpointParts[0]
			domainName = dns.Fqdn(domainName)
			port := 443 // default to 443
			if len(endpointParts) > 1 {
				port, _ = strconv.Atoi(endpointParts[1])
			}
			endpoints[domainName] = append(endpoints[domainName], Endpoint{domainName: domainName, port: port})
		}
	}

	return endpoints
}

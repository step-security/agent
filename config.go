package main

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type config struct {
	Repo             string
	CorrelationId    string
	RunId            string
	WorkingDirectory string
	APIURL           string
	Endpoints        []Endpoint
	EgressPolicy     string
}

type Endpoint struct {
	domainName string
	port       int
}

type configFile struct {
	Repo             string `json:"repo"`
	CorrelationId    string `json:"correlation_id"`
	RunId            string `json:"run_id"`
	WorkingDirectory string `json:"working_directory"`
	APIURL           string `json:"api_url"`
	AllowedEndpoints string `json:"allowed_endpoints"`
	EgressPolicy     string `json:"egress_policy"`
}

// init reads the config file for the agent and initializes config settings
func (c *config) init(configFilePath string) error {
	var configFile configFile
	data, err := ioutil.ReadFile(configFilePath)
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
	return nil
}

func parseEndpoints(allowedEndpoints string) []Endpoint {
	var endpoints []Endpoint
	endpointsArray := strings.Split(allowedEndpoints, " ")
	for _, endpoint := range endpointsArray {
		if len(endpoint) > 0 {
			endpointParts := strings.Split(endpoint, ":")
			domainName := endpointParts[0]
			port := 443 // default to 443
			if len(endpointParts) > 1 {
				port, _ = strconv.Atoi(endpointParts[1])
			}

			endpoints = append(endpoints, Endpoint{domainName: domainName, port: port})
		}
	}

	return endpoints
}

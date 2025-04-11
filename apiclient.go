package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type DNSRecord struct {
	DomainName        string    `json:"domainName"`
	ResolvedIPAddress string    `json:"ipAddress"`
	TimeStamp         time.Time `json:"timestamp"`
}

type Tool struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Parent *Tool  `json:"parent"`
}

type FileEvent struct {
	FileType  string    `json:"filetype"` // this can be source, dependency, artifact
	TimeStamp time.Time `json:"timestamp"`
	Tool      Tool      `json:"tool"`
}

type NetworkConnection struct {
	IPAddress  string    `json:"ipAddress,omitempty"`
	Port       string    `json:"port,omitempty"`
	DomainName string    `json:"domainName,omitempty"`
	TimeStamp  time.Time `json:"timestamp"`
	Tool       Tool      `json:"tool"`
	Status     string    `json:"status,omitempty"`
}

type ApiClient struct {
	Client           *http.Client
	APIURL           string
	DisableTelemetry bool
	EgressPolicy     string
	OneTimeKey       string
}

const agentApiBaseUrl = "https://apiurl/v1"

func (apiclient *ApiClient) sendDNSRecord(correlationId, repo, domainName, ipAddress string) error {

	if !apiclient.DisableTelemetry || apiclient.EgressPolicy == EgressPolicyAudit {
		dnsRecord := &DNSRecord{}

		dnsRecord.DomainName = domainName
		dnsRecord.ResolvedIPAddress = ipAddress
		dnsRecord.TimeStamp = time.Now().UTC()

		url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/dns", apiclient.APIURL, repo, correlationId)

		return apiclient.sendApiRequest("POST", url, dnsRecord)
	}
	return nil
}

func (apiclient *ApiClient) sendNetConnection(correlationId, repo, ipAddress, port, domainName, status string, timestamp time.Time, tool Tool) error {

	if !apiclient.DisableTelemetry || apiclient.EgressPolicy == EgressPolicyAudit {
		networkConnection := &NetworkConnection{}

		networkConnection.IPAddress = ipAddress
		networkConnection.Port = port
		networkConnection.DomainName = domainName
		networkConnection.Status = status
		networkConnection.TimeStamp = timestamp
		networkConnection.Tool = tool

		url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/networkconnection", apiclient.APIURL, repo, correlationId)

		return apiclient.sendApiRequest("POST", url, networkConnection)
	}
	return nil

}

func (apiclient *ApiClient) getSubscriptionStatus(repo string) bool {

	url := fmt.Sprintf("%s/github/%s/actions/subscription", apiclient.APIURL, repo)

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return true
	}

	resp, err := apiclient.Client.Do(req)

	if err != nil {
		return true
	}

	if resp.StatusCode == 403 {
		return false
	}

	return true
}

func (apiclient *ApiClient) getGlobalFeatureFlags() GlobalFeatureFlags {

	url := fmt.Sprintf("%s/global-feature-flags?agent_type=%s", apiclient.APIURL, AgentTypeGitHubHosted)

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return GlobalFeatureFlags{}
	}

	resp, err := apiclient.Client.Do(req)

	if err != nil {
		return GlobalFeatureFlags{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GlobalFeatureFlags{}
	}

	var globalFeatureFlags GlobalFeatureFlags
	err = json.Unmarshal(body, &globalFeatureFlags)
	if err != nil {
		return GlobalFeatureFlags{}
	}

	return globalFeatureFlags
}

func (apiclient *ApiClient) sendApiRequest(method, url string, body interface{}) error {

	jsonData, _ := json.Marshal(body)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))

	if err != nil {
		return err
	}

	req.Header.Add("x-one-time-key", apiclient.OneTimeKey)
	if body != nil {
		req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	}

	retryCounter := 0
	var httpError error
	for retryCounter < 3 {
		_, httpError = apiclient.sendHttpRequest(req)
		if httpError != nil {
			retryCounter++
		} else {
			break
		}
	}

	return httpError
}

func (apiclient *ApiClient) sendHttpRequest(req *http.Request) (*http.Response, error) {
	resp, err := apiclient.Client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API call error, status code: %d", resp.StatusCode)
	}

	return resp, nil
}

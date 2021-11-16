package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/step-security/agent/pkg/artifact"
)

type DNSRecord struct {
	DomainName        string    `json:"domainName"`
	ResolvedIPAddress string    `json:"ipAddress"`
	TimeStamp         time.Time `json:"timestamp"`
}

type Tool struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type FileEvent struct {
	FileType  string    `json:"filetype"` // this can be source, dependency, artifact
	TimeStamp time.Time `json:"timestamp"`
	Tool      Tool      `json:"tool"`
}

type NetworkConnection struct {
	IPAddress string    `json:"ipAddress,omitempty"`
	Port      string    `json:"port,omitempty"`
	TimeStamp time.Time `json:"timestamp"`
	Tool      Tool      `json:"tool"`
	Status    string    `json:"status,omitempty"`
}

type ApiClient struct {
	Client *http.Client
	APIURL string
}

const agentApiBaseUrl = "https://apiurl/v1"

func (apiclient *ApiClient) monitorRun(repo, runid string) error {
	url := fmt.Sprintf("%s/github/%s/actions/runs/%s/monitor", apiclient.APIURL, repo, runid)

	return apiclient.sendApiRequest("POST", url, nil)
}

func (apiclient *ApiClient) sendDNSRecord(correlationId, repo, domainName, ipAddress string) error {

	dnsRecord := &DNSRecord{}

	dnsRecord.DomainName = domainName
	dnsRecord.ResolvedIPAddress = ipAddress
	dnsRecord.TimeStamp = time.Now().UTC()

	url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/dns", apiclient.APIURL, repo, correlationId)

	return apiclient.sendApiRequest("POST", url, dnsRecord)
}

func (apiclient *ApiClient) sendNetConnection(correlationId, repo, ipAddress, port, status string, timestamp time.Time, tool, toolChecksum string) error {

	networkConnection := &NetworkConnection{}

	networkConnection.IPAddress = ipAddress
	networkConnection.Port = port
	networkConnection.Status = status
	networkConnection.TimeStamp = timestamp
	networkConnection.Tool = Tool{Name: tool, SHA256: toolChecksum}

	url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/networkconnection", apiclient.APIURL, repo, correlationId)

	return apiclient.sendApiRequest("POST", url, networkConnection)
}

func (apiclient *ApiClient) sendFileEvent(correlationId, repo, fileType string, timestamp time.Time, tool, toolChecksum string) error {

	fileEvent := &FileEvent{}

	fileEvent.FileType = fileType
	fileEvent.TimeStamp = timestamp
	fileEvent.Tool = Tool{Name: tool, SHA256: toolChecksum}

	url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/fileevent", apiclient.APIURL, repo, correlationId)

	return apiclient.sendApiRequest("POST", url, fileEvent)
}

func (apiclient *ApiClient) sendArtifact(correlationId, repo string, artifact artifact.Artifact) error {

	url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/artifact", apiclient.APIURL, repo, correlationId)

	return apiclient.sendApiRequest("POST", url, artifact)
}

func (apiclient *ApiClient) sendApiRequest(method, url string, body interface{}) error {

	jsonData, _ := json.Marshal(body)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))

	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	}

	resp, err := apiclient.Client.Do(req)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("API call error, status code: %d", resp.StatusCode)
	}

	return nil
}

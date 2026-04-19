package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

type DNSRecord struct {
	DomainName        string    `json:"domainName"`
	ResolvedIPAddress string    `json:"ipAddress"`
	TimeStamp         time.Time `json:"timestamp"`
	MatchedPolicy     string    `json:"matched_policy,omitempty"`
	Reason            string    `json:"reason,omitempty"`
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
	IPAddress     string    `json:"ipAddress,omitempty"`
	Port          string    `json:"port,omitempty"`
	DomainName    string    `json:"domainName,omitempty"`
	TimeStamp     time.Time `json:"timestamp"`
	Tool          Tool      `json:"tool"`
	Status        string    `json:"status,omitempty"`
	MatchedPolicy string    `json:"matched_policy,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}

type ApiClient struct {
	Client           *http.Client
	APIURL           string
	TelemetryURL     string
	DisableTelemetry bool
	EgressPolicy     string
	OneTimeKey       string
}

const agentApiBaseUrl = "https://apiurl/v1"

func (apiclient *ApiClient) sendDNSRecord(correlationId, repo, domainName, ipAddress, matchedPolicy, reason string) error {

	if !apiclient.DisableTelemetry || apiclient.EgressPolicy == EgressPolicyAudit {
		dnsRecord := &DNSRecord{}

		dnsRecord.DomainName = domainName
		dnsRecord.ResolvedIPAddress = ipAddress
		dnsRecord.TimeStamp = time.Now().UTC()
		dnsRecord.MatchedPolicy = matchedPolicy
		dnsRecord.Reason = reason

		url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/dns", apiclient.TelemetryURL, repo, correlationId)

		return apiclient.sendApiRequest("POST", url, dnsRecord)
	}
	return nil
}

func (apiclient *ApiClient) sendNetConnection(correlationId, repo, ipAddress, port, domainName, status, matchedPolicy, reason string, timestamp time.Time, tool Tool) error {

	if !apiclient.DisableTelemetry || apiclient.EgressPolicy == EgressPolicyAudit {
		networkConnection := &NetworkConnection{}

		networkConnection.IPAddress = ipAddress
		networkConnection.Port = port
		networkConnection.DomainName = domainName
		networkConnection.Status = status
		networkConnection.TimeStamp = timestamp
		networkConnection.Tool = tool
		networkConnection.MatchedPolicy = matchedPolicy
		networkConnection.Reason = reason

		url := fmt.Sprintf("%s/github/%s/actions/jobs/%s/networkconnection", apiclient.TelemetryURL, repo, correlationId)

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

	u, err := url.Parse(apiclient.APIURL)
	if err != nil {
		return GlobalFeatureFlags{}
	}

	u.Path = path.Join(u.Path, "global-feature-flags")

	// Add query parameters
	values := url.Values{}
	values.Add("agent_type", AgentTypeOSS)
	values.Add("version", ReleaseTag) // v1.3.6
	u.RawQuery = values.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)

	if err != nil {
		fmt.Println("Error creating request:", err)
		return GlobalFeatureFlags{}
	}

	resp, err := apiclient.Client.Do(req)

	if err != nil {
		fmt.Println("Error sending request:", err)
		return GlobalFeatureFlags{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return GlobalFeatureFlags{}
	}

	var globalFeatureFlags GlobalFeatureFlags
	err = json.Unmarshal(body, &globalFeatureFlags)
	if err != nil {
		fmt.Println("Error unmarshalling response body:", err)
		return GlobalFeatureFlags{}
	}

	return globalFeatureFlags
}

func (apiclient *ApiClient) getGlobalBlocklist() (*GlobalBlocklistResponse, error) {
	url := fmt.Sprintf("%s/global-blocklist", apiclient.APIURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("[getGlobalBlocklist] error occurred while getting global blocklist: %s", err)
	}

	resp, err := apiclient.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[getGlobalBlocklist] error while sending request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[getGlobalBlocklist] response status not okay: status %d", resp.StatusCode)
	}

	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[getGlobalBlocklist] unable to read reqBody: %s", err)
	}

	out := new(GlobalBlocklistResponse)
	err = json.Unmarshal(reqBody, out)
	if err != nil {
		return nil, fmt.Errorf("[getGlobalBlocklist] unable to unmarshal reqBody: %s", err)
	}

	return out, nil
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

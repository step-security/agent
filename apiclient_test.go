package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestHTTPClient uses an explicit transport so these tests keep working
// even after another test has mocked http.DefaultTransport via httpmock.
func newTestHTTPClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{}}
}

func Test_getGithubMetaDomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/github/meta" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"domains":{"actions":["github.com","api.github.com","codeload.github.com","*.github.com","*.actions.githubusercontent.com","objects.githubusercontent.com"]}}`)
	}))
	defer server.Close()

	apiclient := &ApiClient{Client: newTestHTTPClient(), APIURL: server.URL + "/v1"}

	endpoints, err := apiclient.getGithubMetaDomains()
	if err != nil {
		t.Fatalf("getGithubMetaDomains returned error: %v", err)
	}

	// Domains must come back in Fqdn form (trailing dot): wildcard matching
	// in the DNS proxy compares raw suffixes against Fqdn query names, so a
	// dotless wildcard like "*.github.com" would never match.
	want := map[string]bool{
		"github.com.":          false,
		"api.github.com.":      false,
		"codeload.github.com.": false,
		"*.github.com.":        false,
	}
	for _, e := range endpoints {
		if e.port != 443 {
			t.Fatalf("endpoint %s port = %d, want 443", e.domainName, e.port)
		}
		if _, ok := want[e.domainName]; !ok {
			t.Fatalf("unexpected endpoint %q; want Fqdn form, githubusercontent.com domains filtered out", e.domainName)
		}
		want[e.domainName] = true
	}
	for domain, seen := range want {
		if !seen {
			t.Fatalf("expected endpoint %q missing", domain)
		}
	}
}

func Test_getGithubMetaDomains_RetriesOnFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `{"domains":{"actions":["github.com"]}}`)
	}))
	defer server.Close()

	apiclient := &ApiClient{Client: newTestHTTPClient(), APIURL: server.URL + "/v1"}

	endpoints, err := apiclient.getGithubMetaDomains()
	if err != nil {
		t.Fatalf("getGithubMetaDomains returned error: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].domainName != "github.com." {
		t.Fatalf("endpoints = %+v, want [github.com.]", endpoints)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("server called %d times, want 3", got)
	}
}

func Test_getGithubMetaDomains_ErrorAfterRetries(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	apiclient := &ApiClient{Client: newTestHTTPClient(), APIURL: server.URL + "/v1"}

	endpoints, err := apiclient.getGithubMetaDomains()
	if err == nil {
		t.Fatalf("expected error after retries, got endpoints %+v", endpoints)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("server called %d times, want 3", got)
	}
}

func Test_getGlobalFeatureFlags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/global-feature-flags" {
			fmt.Fprint(w, `not json`)
			return
		}
		fmt.Fprint(w, `{"agent_type":"agent-oss","revert_github_dns_experiment":false}`)
	}))
	defer server.Close()

	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedServer.Close()

	tests := []struct {
		name   string
		apiURL string
		want   GlobalFeatureFlags
	}{
		{name: "fetched flags", apiURL: server.URL + "/v1", want: GlobalFeatureFlags{AgentType: AgentTypeOSS}},
		{name: "invalid url", apiURL: "%zz", want: defaultGlobalFeatureFlags()},
		{name: "request error", apiURL: closedServer.URL, want: defaultGlobalFeatureFlags()},
		{name: "invalid response", apiURL: server.URL + "/other", want: defaultGlobalFeatureFlags()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiclient := &ApiClient{Client: newTestHTTPClient(), APIURL: tt.apiURL}

			if got := apiclient.getGlobalFeatureFlags(); got != tt.want {
				t.Fatalf("getGlobalFeatureFlags() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_GetGlobalFeatureFlags_DefaultsWhenUninitialized(t *testing.T) {
	savedManager := globalManager
	globalManager = nil
	defer func() { globalManager = savedManager }()

	if got := GetGlobalFeatureFlags(); !got.RevertGithubDNSExperiment {
		t.Fatalf("GetGlobalFeatureFlags() = %+v, want RevertGithubDNSExperiment true", got)
	}
}

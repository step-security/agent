package main

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
)

func Test_sendDNSRecord(t *testing.T) {
	type args struct {
		correlationId string
		repo          string
		domainName    string
		ipAddress     string
	}

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: agentApiBaseUrl}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/github/owner/repo/actions/jobs/123/dns", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid request", args: args{repo: "owner/repo", correlationId: "123"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := apiclient.sendDNSRecord(tt.args.correlationId, tt.args.repo, tt.args.domainName, tt.args.ipAddress); (err != nil) != tt.wantErr {
				t.Errorf("sendDNSRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_sendNetConnection(t *testing.T) {
	type args struct {
		correlationId string
		repo          string
		ipAddress     string
		port          string
		status        string
		timestamp     time.Time
		tool          Tool
	}

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: agentApiBaseUrl}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/github/owner/repo/actions/jobs/123/networkconnection", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid request", args: args{repo: "owner/repo", correlationId: "123", timestamp: time.Now().UTC()}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := apiclient.sendNetConnection(tt.args.correlationId, tt.args.repo, tt.args.ipAddress,
				tt.args.port, tt.args.status, tt.args.timestamp, tt.args.tool); (err != nil) != tt.wantErr {
				t.Errorf("sendNetConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

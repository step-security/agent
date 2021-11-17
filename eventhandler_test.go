package main

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/jarcoal/httpmock"
)

func TestEventHandler_HandleEvent(t *testing.T) {
	type fields struct {
		CorrelationId        string
		Repo                 string
		ApiClient            *ApiClient
		ProcessConnectionMap map[string]bool
		ProcessFileMap       map[string]bool
		ProcessMap           map[string]*Process
		netMutex             sync.RWMutex
		fileMutex            sync.RWMutex
	}
	type args struct {
		event *Event
	}

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: agentApiBaseUrl}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/github/owner/repo/actions/jobs/123/networkconnection", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/github/owner/repo/actions/jobs/123/fileevent", agentApiBaseUrl),
		httpmock.NewStringResponder(200, ""))

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{name: "netMonitorEvent", fields: fields{CorrelationId: "123", Repo: "owner/repo", ApiClient: apiclient, ProcessConnectionMap: make(map[string]bool)},
			args: args{event: &Event{IPAddress: "2.2.2.2", Port: "443", EventType: netMonitorTag, Exe: "/path/to/exe"}}},
		{name: "fileMonitorEvent", fields: fields{CorrelationId: "123", Repo: "owner/repo", ApiClient: apiclient, ProcessFileMap: make(map[string]bool)},
			args: args{event: &Event{EventType: fileMonitorTag, Exe: "/path/to/exe", FileName: ".git/objects"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventHandler := &EventHandler{
				CorrelationId:        tt.fields.CorrelationId,
				Repo:                 tt.fields.Repo,
				ApiClient:            tt.fields.ApiClient,
				ProcessConnectionMap: tt.fields.ProcessConnectionMap,
				ProcessFileMap:       tt.fields.ProcessFileMap,
				ProcessMap:           tt.fields.ProcessMap,
				netMutex:             tt.fields.netMutex,
				fileMutex:            tt.fields.fileMutex,
			}
			eventHandler.HandleEvent(tt.args.event)
		})
	}
}

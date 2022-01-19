package main

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/miekg/dns"
)

func TestDNSProxy_getResponse(t *testing.T) {
	type fields struct {
		Cache            *Cache
		EgressPolicy     string
		AllowedEndpoints map[string][]Endpoint
	}
	type args struct {
		requestMsg *dns.Msg
	}
	auditCache := InitCache(EgressPolicyAudit)
	blockCache := InitCache(EgressPolicyBlock)
	rrDnsGoogle, _ := dns.NewRR("dns.google. IN A 8.8.8.8")
	rrDnsTest, _ := dns.NewRR("test.com. IN A 67.225.146.248")
	rrDnsNotAllowed, _ := dns.NewRR(fmt.Sprintf("notallowed.com. IN A %s", StepSecuritySinkHoleIPAddress))
	rrDnsAllowed, _ := dns.NewRR("allowed.com. IN A 67.225.146.248")
	allowedEndpoints := make(map[string][]Endpoint)
	allowedEndpoints["allowed.com."] = append(allowedEndpoints["allowed.com."], Endpoint{domainName: "allowed.com"})
	allowedEndpointsTest := make(map[string][]Endpoint)
	allowedEndpointsTest["test.com."] = append(allowedEndpointsTest["test.com."], Endpoint{domainName: "test.com"})

	apiclient := &ApiClient{Client: &http.Client{}, APIURL: agentApiBaseUrl}

	httpmock.ActivateNonDefault(apiclient.Client)

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=test.com.&type=a",
		httpmock.NewStringResponder(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"test.com.","type":1}],"Answer":[{"name":"test.com.","type":1,"TTL":3080,"data":"67.225.146.248"}]}`))

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=allowed.com.&type=a",
		httpmock.NewStringResponder(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"allowed.com.","type":1}],"Answer":[{"name":"allowed.com.","type":1,"TTL":3080,"data":"67.225.146.248"}]}`))

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=notfound.com.&type=a",
		httpmock.NewStringResponder(200, `{"Status":3,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"notfound.com.","type":1}],"Authority":[{"name":"com.","type":6,"TTL":900,"data":"a.gtld-servers.net. nstld.verisign-grs.com. 1640040308 1800 900 604800 86400"}],"Comment":"Response from 2001:503:231d::2:30."}`))

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *dns.Msg
		wantErr bool
	}{
		{name: "type A dns.google",
			fields:  fields{Cache: &auditCache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "dns.google.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsGoogle}},
			wantErr: false,
		},
		{name: "type A test.com",
			fields:  fields{Cache: &auditCache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsTest}},
			wantErr: false,
		},
		{name: "type AAAA test.com",
			fields:  fields{Cache: &auditCache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeAAAA}}}},
			want:    &dns.Msg{},
			wantErr: true,
		},
		{name: "type A notallowed.com",
			fields:  fields{Cache: &blockCache, EgressPolicy: EgressPolicyBlock, AllowedEndpoints: allowedEndpoints},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "notallowed.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsNotAllowed}},
			wantErr: false,
		},
		{name: "type A test.com egress policy cached",
			fields:  fields{Cache: &blockCache, EgressPolicy: EgressPolicyBlock, AllowedEndpoints: allowedEndpointsTest},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsTest}},
			wantErr: false,
		},
		{name: "type A allowed.com egress policy",
			fields:  fields{Cache: &blockCache, EgressPolicy: EgressPolicyBlock, AllowedEndpoints: allowedEndpoints},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "allowed.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsAllowed}},
			wantErr: false,
		},
		{name: "type A notfound.com",
			fields:  fields{Cache: &auditCache, EgressPolicy: EgressPolicyAudit},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "notfound.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			proxy := &DNSProxy{
				Cache:            tt.fields.Cache,
				ApiClient:        apiclient,
				EgressPolicy:     tt.fields.EgressPolicy,
				AllowedEndpoints: tt.fields.AllowedEndpoints,
				ReverseIPLookup:  make(map[string]string),
			}
			got, err := proxy.getResponse(tt.args.requestMsg)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSProxy.getResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DNSProxy.getResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSProxy_auditCacheTTL(t *testing.T) {
	apiclient := &ApiClient{Client: &http.Client{}, APIURL: agentApiBaseUrl}

	httpmock.ActivateNonDefault(apiclient.Client)

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=domain12345.com.&type=a",
		httpmock.ResponderFromMultipleResponses(
			[]*http.Response{
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain12345.com.","type":1}],"Answer":[{"name":"domain12345.com.","type":1,"TTL":30,"data":"68.68.68.68"}]}`),
				httpmock.NewStringResponse(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"domain12345.com.","type":1}],"Answer":[{"name":"domain12345.com.","type":1,"TTL":30,"data":"68.68.68.68"}]}`),
			},
			t.Log))

	cache := InitCache(EgressPolicyAudit)

	proxy := &DNSProxy{
		Cache:           &cache,
		ApiClient:       apiclient,
		EgressPolicy:    EgressPolicyAudit,
		ReverseIPLookup: make(map[string]string),
	}

	// should call httpmock
	proxy.getResponse(&dns.Msg{Question: []dns.Question{{Name: "domain12345.com.", Qtype: dns.TypeA}}})

	time.Sleep(2 * time.Second)

	// should get from cache
	proxy.getResponse(&dns.Msg{Question: []dns.Question{{Name: "domain12345.com.", Qtype: dns.TypeA}}})

	time.Sleep(30 * time.Second)

	// should call httpmock
	proxy.getResponse(&dns.Msg{Question: []dns.Question{{Name: "domain12345.com.", Qtype: dns.TypeA}}})

	info := httpmock.GetCallCountInfo()
	count := info["GET https://dns.google/resolve?name=domain12345.com.&type=a"]
	if count != 2 {
		t.Errorf("incorrect call count %d, expected 2, %v", count, info)
	}
}

func Test_getDomainFromCloudAppFormat(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "prod.cloudflare.com", args: args{domain: "production.cloudflare.docker.com.mma5zatft5wupo5mzspaixdheh.bx.internal.cloudapp.net."}, want: "production.cloudflare.docker.com."},
		{name: "host.docker.internal", args: args{domain: "host.docker.internal.mma5zatft5wupo5mzspaixdheh.bx.internal.cloudapp.net."}, want: "host.docker.internal."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getDomainFromCloudAppFormat(tt.args.domain); got != tt.want {
				t.Errorf("getDomainFromCloudAppFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

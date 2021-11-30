package main

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/miekg/dns"
)

func init() {
	httpmock.Activate()
}

func TestDNSProxy_getResponse(t *testing.T) {
	type fields struct {
		Cache *Cache
	}
	type args struct {
		requestMsg *dns.Msg
	}
	Cache := InitCache(60 * 1000000000)
	rrDnsGoogle, _ := dns.NewRR("dns.google. IN A 8.8.8.8")
	rrDnsTest, _ := dns.NewRR("test.com. IN A 67.225.146.248")

	apiclient := &ApiClient{Client: &http.Client{}}

	httpmock.RegisterResponder("GET", "https://dns.google/resolve?name=test.com.&type=a",
		httpmock.NewStringResponder(200, `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"test.com.","type":1}],"Answer":[{"name":"test.com.","type":1,"TTL":3080,"data":"67.225.146.248"}]}`))

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *dns.Msg
		wantErr bool
	}{
		{name: "type A dns.google",
			fields:  fields{Cache: &Cache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "dns.google.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsGoogle}},
			wantErr: false,
		},
		{name: "type A test.com",
			fields:  fields{Cache: &Cache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeA}}}},
			want:    &dns.Msg{Answer: []dns.RR{rrDnsTest}},
			wantErr: false,
		},
		{name: "type AAAA test.com",
			fields:  fields{Cache: &Cache},
			args:    args{requestMsg: &dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeAAAA}}}},
			want:    &dns.Msg{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			proxy := &DNSProxy{
				Cache:     tt.fields.Cache,
				ApiClient: apiclient,
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

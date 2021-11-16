package main

import (
	"reflect"
	"testing"
)

func Test_config_init(t *testing.T) {

	type args struct {
		configFilePath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "config not found",
			args: args{
				configFilePath: "./testfiles/nosuchfile.json",
			},
			wantErr: true},
		{name: "valid config",
			args: args{
				configFilePath: "./testfiles/agent.json",
			},
			wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config{}
			if err := c.init(tt.args.configFilePath); (err != nil) != tt.wantErr {
				t.Errorf("config.init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseEndpoints(t *testing.T) {
	type args struct {
		allowedEndpoints string
	}
	tests := []struct {
		name string
		args args
		want []Endpoint
	}{
		{name: "endpoints with and without port",
			args: args{allowedEndpoints: "proxy.golang.org:443 api.github.com"},
			want: []Endpoint{{"proxy.golang.org", 443}, {"api.github.com", 443}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseEndpoints(tt.args.allowedEndpoints); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

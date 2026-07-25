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

func Test_parseExemptFiles(t *testing.T) {
	type args struct {
		exemptFiles string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{name: "empty", args: args{exemptFiles: ""}, want: nil},
		{name: "one path per line", args: args{exemptFiles: "dist/index.js\npackage-lock.json"}, want: []string{"dist/index.js", "package-lock.json"}},
		{name: "trims whitespace and blank lines", args: args{exemptFiles: "  dist/index.js  \n\n  go.sum "}, want: []string{"dist/index.js", "go.sum"}},
		{name: "preserves spaces within a path", args: args{exemptFiles: "my dir/file.txt\nother.txt"}, want: []string{"my dir/file.txt", "other.txt"}},
		{name: "handles CRLF", args: args{exemptFiles: "dist/index.js\r\npackage-lock.json\r\n"}, want: []string{"dist/index.js", "package-lock.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseExemptFiles(tt.args.exemptFiles); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseExemptFiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseEndpoints(t *testing.T) {
	type args struct {
		allowedEndpoints string
	}

	wantEndpoints := make(map[string][]Endpoint)
	wantEndpoints["proxy.golang.org."] = append(wantEndpoints["proxy.golang.org."], Endpoint{"proxy.golang.org.", 443})
	wantEndpoints["api.github.com."] = append(wantEndpoints["api.github.com."], Endpoint{"api.github.com.", 443})

	tests := []struct {
		name string
		args args
		want map[string][]Endpoint
	}{
		{name: "endpoints with and without port",
			args: args{allowedEndpoints: "proxy.golang.org:443 api.github.com"},
			want: wantEndpoints,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseEndpoints(tt.args.allowedEndpoints); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

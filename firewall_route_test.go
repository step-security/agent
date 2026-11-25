package main

import (
	"strings"
	"testing"
)

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestParseDefaultInterface(t *testing.T) {
	tests := []struct {
		name    string
		routes  string
		want    string
		wantErr bool
	}{
		{
			name: "azure eth0",
			routes: "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "aws enp39s0 with docker0",
			routes: "enp39s0\t00000000\t01001FAC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n",
			want: "enp39s0",
		},
		{
			name: "lowest metric wins",
			routes: "eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
				"ens5\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "ens5",
		},
		{
			name:    "default route down is skipped",
			routes:  "eth0\t00000000\t0100000A\t0002\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantErr: true,
		},
		{
			name:    "no default route",
			routes:  "eth0\t0000000A\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDefaultInterface(strings.NewReader(routeHeader + tt.routes))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDefaultInterface() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseDefaultInterface() = %q, want %q", got, tt.want)
			}
		})
	}
}

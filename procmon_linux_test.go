//go:build linux
// +build linux

package main

import "testing"

func Test_getProcessExe(t *testing.T) {
	type args struct {
		pid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "root_pid", args: args{pid: "1"}, wantErr: false},
		{name: "unknown_pid", args: args{pid: "6666"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getProcessExe(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("getProcessExe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

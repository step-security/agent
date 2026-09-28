//go:build linux
// +build linux

package main

import (
	"os"
	"testing"
)

func Test_fileMonitorAuditRule(t *testing.T) {
	tests := []struct {
		name             string
		workingDirectory string
		goarch           string
		want             string
	}{
		{
			name:             "arm64 excludes unsupported syscalls",
			workingDirectory: "/home/runner/work/repo",
			goarch:           "arm64",
			want:             "-a exit,always -F dir=/home/runner/work/repo -F perm=wa -S openat -S renameat -k filemon",
		},
		{
			name:             "default includes open and rename syscalls",
			workingDirectory: "/home/runner/work/repo",
			goarch:           "amd64",
			want:             "-a exit,always -F dir=/home/runner/work/repo -F perm=wa -S open -S openat -S rename -S renameat -k filemon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileMonitorAuditRule(tt.workingDirectory, tt.goarch); got != tt.want {
				t.Errorf("fileMonitorAuditRule() = %q, want %q", got, tt.want)
			}
		})
	}
}

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
	_, ciTest := os.LookupEnv("CI")
	if ciTest {
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

}

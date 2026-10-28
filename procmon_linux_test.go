//go:build linux
// +build linux

package main

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
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

// fakeNetlink replays audit records and errors to AuditClient.Receive.
type fakeNetlink struct {
	steps []fakeNetlinkStep
}

type fakeNetlinkStep struct {
	msgType auparse.AuditMessageType
	text    string
	err     error
}

func (f *fakeNetlink) Receive(bool, libaudit.NetlinkParser) ([]syscall.NetlinkMessage, error) {
	if len(f.steps) == 0 {
		return nil, syscall.EBADF
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	if step.err != nil {
		return nil, step.err
	}
	return []syscall.NetlinkMessage{{
		Header: syscall.NlMsghdr{Type: uint16(step.msgType)},
		Data:   []byte(step.text),
	}}, nil
}

func (f *fakeNetlink) Send(syscall.NetlinkMessage) (uint32, error) { return 0, nil }
func (f *fakeNetlink) Close() error                                { return nil }

func TestReceiveContinuesAfterOverflow(t *testing.T) {
	netlink := &fakeNetlink{steps: []fakeNetlinkStep{
		{err: syscall.ENOBUFS},
		{msgType: auparse.AUDIT_SYSCALL, text: `audit(1700000000.123:42): arch=c000003e syscall=44 success=yes exit=121 a0=3 a1=7f00 a2=79 a3=0 items=0 ppid=1 pid=100 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="python3" exe="/usr/bin/python3.12" key="netmon"`},
		{err: syscall.ENOBUFS},
		{msgType: auparse.AUDIT_PROCTITLE, text: `audit(1700000000.123:42): proctitle=707974686F6E33`},
		{msgType: auparse.AUDIT_EOE, text: `audit(1700000000.123:42): `},
	}}
	p := &ProcessMonitor{}

	err := p.receive(&libaudit.AuditClient{Netlink: netlink})

	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("receive should stop only on the terminal error, got %v", err)
	}
	if p.receiveOverflow != 2 {
		t.Fatalf("expected 2 overflows counted, got %d", p.receiveOverflow)
	}
	if len(netlink.steps) != 0 {
		t.Fatalf("records after an overflow were not read: %d left", len(netlink.steps))
	}
	if p.records != 2 {
		t.Fatalf("expected the SYSCALL and PROCTITLE records to be processed, got %d", p.records)
	}
	if len(p.Events) != 0 {
		t.Fatalf("expected the event to be retired on EOE, got %d pending", len(p.Events))
	}
}

//go:build linux
// +build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

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
	block   chan struct{} // Receive waits on it, then reports the client closed
}

func (f *fakeNetlink) Receive(bool, libaudit.NetlinkParser) ([]syscall.NetlinkMessage, error) {
	if len(f.steps) == 0 {
		return nil, syscall.EBADF
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	if step.block != nil {
		<-step.block
		return nil, syscall.EBADF
	}
	if step.err != nil {
		return nil, step.err
	}
	return []syscall.NetlinkMessage{{
		Header: syscall.NlMsghdr{Type: uint16(step.msgType)},
		Data:   []byte(step.text),
	}}, nil
}

func (f *fakeNetlink) Send(syscall.NetlinkMessage) (uint32, error)       { return 0, nil }
func (f *fakeNetlink) SendNoWait(syscall.NetlinkMessage) (uint32, error) { return 0, nil }
func (f *fakeNetlink) Close() error                                      { return nil }

func TestReceiveKeepsGoingUntilTheClientIsClosed(t *testing.T) {
	netlink := &fakeNetlink{steps: []fakeNetlinkStep{
		{err: syscall.ENOBUFS},
		{err: syscall.EINVAL},
		{msgType: auparse.AUDIT_SYSCALL, text: `audit(1700000000.123:43): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd a2=10 a3=0 items=0 ppid=1 pid=101 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="curl" exe="/usr/bin/curl" key="netmon"`},
		{msgType: auparse.AUDIT_SOCKADDR, text: `audit(1700000000.123:43): saddr=020001BBC000020A0000000000000000`},
		{msgType: auparse.AUDIT_CWD, text: `not an audit record`},
		{err: syscall.ENOBUFS},
		{msgType: auparse.AUDIT_PROCTITLE, text: `audit(1700000000.123:43): proctitle=6375726C`},
		{msgType: auparse.AUDIT_EOE, text: `audit(1700000000.123:43): `},
	}}
	var mu sync.Mutex
	var dispatched []Event
	p := &ProcessMonitor{dispatchEvent: func(e *Event) {
		mu.Lock()
		dispatched = append(dispatched, *e)
		mu.Unlock()
	}}

	err := p.receive(&libaudit.AuditClient{Netlink: netlink})

	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("receive should stop only when the client is closed, got %v", err)
	}
	if len(netlink.steps) != 0 {
		t.Fatalf("not every message was read: %d left", len(netlink.steps))
	}
	if got := p.receiveOverflow.Load(); got != 2 {
		t.Fatalf("expected 2 overflows counted, got %d", got)
	}
	if got := p.receiveErrors.Load(); got != 1 {
		t.Fatalf("expected 1 other receive error counted, got %d", got)
	}
	if got := p.invalidRecords.Load(); got != 1 {
		t.Fatalf("expected the unparsable record to be dropped, got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dispatched) != 1 || dispatched[0].IPAddress != "192.0.2.10" || dispatched[0].Port != "443" {
		t.Fatalf("expected the connect to be dispatched once, got %+v", dispatched)
	}
}

func TestReceiveDeliversTimedOutEventsWhileIdle(t *testing.T) {
	connect := func(seq int, last bool) []fakeNetlinkStep {
		steps := []fakeNetlinkStep{
			{msgType: auparse.AUDIT_SYSCALL, text: fmt.Sprintf(`audit(1700000000.123:%d): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd a2=10 a3=0 items=0 ppid=1 pid=%d auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="curl" exe="/usr/bin/curl" key="netmon"`, seq, seq)},
			{msgType: auparse.AUDIT_SOCKADDR, text: fmt.Sprintf(`audit(1700000000.123:%d): saddr=020001BBC000020A0000000000000000`, seq)},
		}
		if last {
			steps = append(steps, fakeNetlinkStep{msgType: auparse.AUDIT_PROCTITLE, text: fmt.Sprintf(`audit(1700000000.123:%d): proctitle=6375726C`, seq)})
		}
		return steps
	}
	release := make(chan struct{})
	var steps []fakeNetlinkStep
	steps = append(steps, connect(79, true)...)  // complete, delivered right away
	steps = append(steps, connect(80, false)...) // never completes
	steps = append(steps, connect(81, true)...)  // complete, but behind 80
	steps = append(steps, fakeNetlinkStep{block: release})
	netlink := &fakeNetlink{steps: steps}

	var mu sync.Mutex
	var pids []string
	p := &ProcessMonitor{dispatchEvent: func(e *Event) {
		mu.Lock()
		pids = append(pids, e.Pid)
		mu.Unlock()
	}}
	delivered := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), pids...)
	}

	result := make(chan error, 1)
	go func() { result <- p.receive(&libaudit.AuditClient{Netlink: netlink}) }()

	// 79 completes on its PROCTITLE, well before the timeout
	completeBy := time.Now().Add(reassemblerTimeout / 2)
	for len(delivered()) < 1 && time.Now().Before(completeBy) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := delivered(); fmt.Sprint(got) != "[79]" {
		t.Fatalf("expected 79 to be delivered when it completed, got %v", got)
	}

	// while receive is blocked, only the maintenance goroutine can deliver 80 and 81
	deadline := time.Now().Add(reassemblerTimeout + 2*time.Second)
	for len(delivered()) < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := delivered(); fmt.Sprint(got) != "[79 80 81]" {
		t.Fatalf("expected 79, then 80 and 81 after the timeout, got %v", got)
	}

	close(release)
	if err := <-result; !errors.Is(err, syscall.EBADF) {
		t.Fatalf("receive should stop when the client is closed, got %v", err)
	}
	if got := delivered(); len(got) != 3 {
		t.Fatalf("no event should be delivered twice, got %v", got)
	}
}

func TestReceiveWaitsForMaintenanceBeforeReturning(t *testing.T) {
	release := make(chan struct{})
	netlink := &fakeNetlink{steps: []fakeNetlinkStep{
		// an incomplete connect that only the maintenance goroutine can deliver
		{msgType: auparse.AUDIT_SYSCALL, text: `audit(1700000000.123:95): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd a2=10 a3=0 items=0 ppid=1 pid=95 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="curl" exe="/usr/bin/curl" key="netmon"`},
		{msgType: auparse.AUDIT_SOCKADDR, text: `audit(1700000000.123:95): saddr=020001BBC000020A0000000000000000`},
		{block: release},
	}}
	inCallback := make(chan struct{})
	finishCallback := make(chan struct{})
	p := &ProcessMonitor{dispatchEvent: func(*Event) {
		close(inCallback)
		<-finishCallback
	}}

	result := make(chan error, 1)
	go func() { result <- p.receive(&libaudit.AuditClient{Netlink: netlink}) }()

	select {
	case <-inCallback:
	case <-time.After(reassemblerTimeout + 2*time.Second):
		t.Fatalf("maintenance did not deliver the timed out event")
	}

	// the client closes while the maintenance callback is still running
	close(release)
	select {
	case err := <-result:
		t.Fatalf("receive returned (%v) while a maintenance callback was running", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(finishCallback)
	if err := <-result; !errors.Is(err, syscall.EBADF) {
		t.Fatalf("receive should stop when the client is closed, got %v", err)
	}
}

// fakeQueueControl records the kernel queue settings it is asked to change.
type fakeQueueControl struct {
	calls []string
	err   error
}

func (f *fakeQueueControl) SetFailure(fm libaudit.FailureMode, _ libaudit.WaitMode) error {
	f.calls = append(f.calls, fmt.Sprintf("failure=%d", fm))
	return f.err
}

func (f *fakeQueueControl) SetBacklogLimit(limit uint32, _ libaudit.WaitMode) error {
	f.calls = append(f.calls, fmt.Sprintf("backlog_limit=%d", limit))
	return f.err
}

func (f *fakeQueueControl) SetBacklogWaitTime(waitTime int32, _ libaudit.WaitMode) error {
	f.calls = append(f.calls, fmt.Sprintf("backlog_wait_time=%d", waitTime))
	return f.err
}

func (f *fakeQueueControl) SetRateLimit(limit uint32, _ libaudit.WaitMode) error {
	f.calls = append(f.calls, fmt.Sprintf("rate_limit=%d", limit))
	return f.err
}

func Test_configureBackpressure(t *testing.T) {
	const waitTimeSupported = libaudit.AuditFeatureBitmapBacklogWaitTime
	cases := []struct {
		name   string
		status libaudit.AuditStatus
		want   []string
	}{
		{
			name:   "kernel defaults with wait time support",
			status: libaudit.AuditStatus{Enabled: 1, Failure: 1, BacklogLimit: 64, BacklogWaitTime: 60000, FeatureBitmap: waitTimeSupported},
			want:   []string{"failure=0", "backlog_limit=8192", "backlog_wait_time=0"},
		},
		{
			name:   "panic failure mode is made silent before dropping",
			status: libaudit.AuditStatus{Enabled: 1, Failure: 2, BacklogLimit: 8192, FeatureBitmap: waitTimeSupported},
			want:   []string{"failure=0", "backlog_wait_time=0"},
		},
		{
			name:   "no wait time support falls back to a rate limit",
			status: libaudit.AuditStatus{Enabled: 1, BacklogLimit: 64},
			want:   []string{"backlog_limit=8192", "rate_limit=5000"},
		},
		{
			name:   "existing rate limit is cleared when wait time is supported",
			status: libaudit.AuditStatus{Enabled: 1, BacklogLimit: 8192, RateLimit: 100, FeatureBitmap: waitTimeSupported},
			want:   []string{"backlog_wait_time=0", "rate_limit=0"},
		},
		{
			name:   "fallback already applied",
			status: libaudit.AuditStatus{Enabled: 1, BacklogLimit: 8192, RateLimit: 5000},
			want:   nil,
		},
		{
			name:   "locked audit config is left alone",
			status: libaudit.AuditStatus{Enabled: 2, BacklogLimit: 64, FeatureBitmap: waitTimeSupported},
			want:   nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeQueueControl{}
			status := c.status
			if err := configureBackpressure(f, &status); err != nil {
				t.Fatalf("configureBackpressure() error = %v", err)
			}
			if fmt.Sprint(f.calls) != fmt.Sprint(c.want) {
				t.Errorf("calls = %v, want %v", f.calls, c.want)
			}
		})
	}
}

func Test_configureBackpressure_error(t *testing.T) {
	f := &fakeQueueControl{err: errors.New("EPERM")}
	status := libaudit.AuditStatus{Enabled: 1, Failure: 2, BacklogLimit: 64, FeatureBitmap: libaudit.AuditFeatureBitmapBacklogWaitTime}
	if err := configureBackpressure(f, &status); err == nil {
		t.Fatal("configureBackpressure() error = nil, want error")
	}
	if len(f.calls) != 1 {
		t.Errorf("calls = %v, want to stop before any drop setting", f.calls)
	}
}

func Test_noteKernelLost(t *testing.T) {
	p := &ProcessMonitor{}
	steps := []struct {
		current   uint32
		wantTotal int64
	}{
		{10, 0},  // first reading after start: 10 were lost before the agent
		{10, 0},  // nothing new
		{25, 15}, // 15 new
		{3, 18},  // counter was reset, 3 new since the reset
		{3, 18},
	}
	last := uint32(10)
	for i, s := range steps {
		last = p.noteKernelLost(last, s.current)
		if last != s.current {
			t.Errorf("step %d: returned %d, want %d", i, last, s.current)
		}
		if got := p.kernelLost.Load(); got != s.wantTotal {
			t.Errorf("step %d: kernelLost = %d, want %d", i, got, s.wantTotal)
		}
	}
}

func Test_monitorKernelLost_stops(t *testing.T) {
	p := &ProcessMonitor{}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		p.monitorKernelLost(0, done)
		close(stopped)
	}()
	close(done)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorKernelLost did not stop after done was closed")
	}
}

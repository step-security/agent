package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestProcessMonitor_PrepareEvent(t *testing.T) {
	processMonitor := &ProcessMonitor{}
	processMonitor.Events = make(map[int]*Event)

	netEventPart1 := make(map[string]interface{})
	netEventPart1["tags"] = []string{"netmon"}
	netEventPart1["syscall"] = "connect"

	netEventPart2 := make(map[string]interface{})
	netEventPart2["addr"] = "2.2.2.2"
	netEventPart2["port"] = "443"

	processMonitor.PrepareEvent(1, netEventPart1)
	processMonitor.PrepareEvent(1, netEventPart2)

	isReady := isEventReady(processMonitor.Events[1])

	if !isReady {
		t.Errorf("Event ready expected")
	}

	fileEventPart1 := make(map[string]interface{})
	fileEventPart1["tags"] = []string{"filemon"}
	fileEventPart1["syscall"] = "open"

	fileEventPart2 := make(map[string]interface{})
	fileEventPart2["nametype"] = "CREATE"
	fileEventPart2["name"] = "file1.txt"

	fileEventPart3 := make(map[string]interface{})
	fileEventPart3["cwd"] = "/dir"

	// Testing procmon.go#93 [Process Start]
	fileEventPart4 := make(map[string]interface{})
	fileEventPart4["argc"] = "2"
	fileEventPart4["a0"] = "argv1"
	fileEventPart4["a1"] = "argv2"

	// In procmon.go [Process Start] section,
	// we are converting `argc` to INT.
	// Because of below code, we will hit the error,
	// in which we are unable to convert argc to INT.
	// So, main intention was to cover that error handling block.
	fileEventPart5 := make(map[string]interface{})
	fileEventPart5["argc"] = []string{"failed"}
	// ===== END =====

	processMonitor.PrepareEvent(2, fileEventPart1)
	processMonitor.PrepareEvent(2, fileEventPart2)
	processMonitor.PrepareEvent(2, fileEventPart3)

	processMonitor.PrepareEvent(2, fileEventPart4)
	processMonitor.PrepareEvent(2, fileEventPart5)

	isReady = isEventReady(processMonitor.Events[2])

	if !isReady {
		t.Errorf("Event ready expected")
	}
}

func parseAuditRecord(t *testing.T, msgType auparse.AuditMessageType, text string) *auparse.AuditMessage {
	t.Helper()
	message, err := auparse.Parse(msgType, text)
	if err != nil {
		t.Fatalf("parse %v: %v", msgType, err)
	}
	return message
}

func TestHandleRecordRetiresSendWithoutAddressOnEOE(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}

	// send() on a connected socket: sendto with no SOCKADDR record
	records := []struct {
		msgType auparse.AuditMessageType
		text    string
	}{
		{auparse.AUDIT_SYSCALL, `audit(1700000000.123:42): arch=c000003e syscall=44 success=yes exit=121 a0=3 a1=7f0000000000 a2=79 a3=0 items=0 ppid=1 pid=100 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="python3" exe="/usr/bin/python3.12" key="netmon"`},
		{auparse.AUDIT_PROCTITLE, `audit(1700000000.123:42): proctitle=707974686F6E33`},
	}
	for _, r := range records {
		if event := p.handleRecord(r.msgType, parseAuditRecord(t, r.msgType, r.text)); event != nil {
			t.Fatalf("send without an address must not be dispatched, got %+v", event)
		}
	}
	if event, ok := p.Events[42]; !ok || event.EventType != netMonitorTag || event.Syscall != "sendto" {
		t.Fatalf("expected a pending sendto event before EOE, got %+v", p.Events[42])
	}

	p.handleRecord(auparse.AUDIT_EOE, parseAuditRecord(t, auparse.AUDIT_EOE, `audit(1700000000.123:42): `))
	if len(p.Events) != 0 {
		t.Fatalf("expected no pending events after EOE, got %d", len(p.Events))
	}
}

func TestHandleRecordDispatchesConnectBeforeEOE(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}

	syscallRecord := `audit(1700000000.456:43): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd00000000 a2=10 a3=0 items=0 ppid=1 pid=101 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="curl" exe="/usr/bin/curl" key="netmon"`
	if event := p.handleRecord(auparse.AUDIT_SYSCALL, parseAuditRecord(t, auparse.AUDIT_SYSCALL, syscallRecord)); event != nil {
		t.Fatalf("connect is not ready before its address, got %+v", event)
	}

	// 192.0.2.10:443
	sockaddr := `audit(1700000000.456:43): saddr=020001BBC000020A0000000000000000`
	event := p.handleRecord(auparse.AUDIT_SOCKADDR, parseAuditRecord(t, auparse.AUDIT_SOCKADDR, sockaddr))
	if event == nil {
		t.Fatalf("expected connect to be dispatched once its address arrives")
	}
	if event.EventType != netMonitorTag || event.Syscall != "connect" || event.IPAddress != "192.0.2.10" || event.Port != "443" || !event.SentForProcessing {
		t.Fatalf("unexpected dispatched event %+v", event)
	}
	if again := p.handleRecord(auparse.AUDIT_PROCTITLE, parseAuditRecord(t, auparse.AUDIT_PROCTITLE, `audit(1700000000.456:43): proctitle=6375726C`)); again != nil {
		t.Fatalf("connect must be dispatched only once")
	}

	p.handleRecord(auparse.AUDIT_EOE, parseAuditRecord(t, auparse.AUDIT_EOE, `audit(1700000000.456:43): `))
	if len(p.Events) != 0 {
		t.Fatalf("expected no pending events after EOE, got %d", len(p.Events))
	}
	if event.IPAddress != "192.0.2.10" {
		t.Fatalf("retiring the sequence must not change the dispatched event")
	}
}

type auditRecord struct {
	msgType auparse.AuditMessageType
	text    string
}

// feedRecords passes records through handleRecord and returns the dispatched events.
func feedRecords(t *testing.T, p *ProcessMonitor, records []auditRecord) []*Event {
	t.Helper()
	var dispatched []*Event
	for _, r := range records {
		if event := p.handleRecord(r.msgType, parseAuditRecord(t, r.msgType, r.text)); event != nil {
			// copy, so later records for the sequence do not hide what was dispatched
			snapshot := *event
			dispatched = append(dispatched, &snapshot)
		}
	}
	return dispatched
}

func TestHandleRecordDispatchesDetectionsOnce(t *testing.T) {
	tests := []struct {
		name    string
		records []auditRecord
		check   func(*Event) bool
	}{
		{
			name: "process start",
			records: []auditRecord{
				{auparse.AUDIT_SYSCALL, `audit(1700000001.000:50): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 a2=55d2 a3=0 items=2 ppid=1 pid=200 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="ls" exe="/usr/bin/ls" key="procmon"`},
				{auparse.AUDIT_EXECVE, `audit(1700000001.000:50): argc=2 a0="ls" a1="-l"`},
				{auparse.AUDIT_CWD, `audit(1700000001.000:50): cwd="/home/runner/work"`},
				{auparse.AUDIT_PATH, `audit(1700000001.000:50): item=0 name="/usr/bin/ls" inode=10 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				{auparse.AUDIT_PROCTITLE, `audit(1700000001.000:50): proctitle=6C73002D6C`},
				{auparse.AUDIT_EOE, `audit(1700000001.000:50): `},
			},
			check: func(e *Event) bool {
				return e.EventType == processMonitorTag && len(e.ProcessArguments) == 2 && e.Path == "/home/runner/work"
			},
		},
		{
			name: "file write",
			records: []auditRecord{
				{auparse.AUDIT_SYSCALL, `audit(1700000002.000:51): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55d0 a2=241 a3=1b6 items=2 ppid=1 pid=201 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="bash" exe="/usr/bin/bash" key="filemon"`},
				{auparse.AUDIT_CWD, `audit(1700000002.000:51): cwd="/home/runner/work/repo"`},
				{auparse.AUDIT_PATH, `audit(1700000002.000:51): item=1 name="out.txt" inode=11 dev=08:01 mode=0100644 ouid=1001 ogid=1001 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				{auparse.AUDIT_PROCTITLE, `audit(1700000002.000:51): proctitle=62617368`},
				{auparse.AUDIT_EOE, `audit(1700000002.000:51): `},
			},
			check: func(e *Event) bool {
				return e.EventType == fileMonitorTag && e.FileName == "out.txt" && e.Path == "/home/runner/work/repo"
			},
		},
		{
			name: "sendto with an address",
			records: []auditRecord{
				{auparse.AUDIT_SYSCALL, `audit(1700000003.000:52): arch=c000003e syscall=44 success=yes exit=40 a0=5 a1=7f00 a2=28 a3=0 items=0 ppid=1 pid=202 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="dig" exe="/usr/bin/dig" key="netmon"`},
				// 192.0.2.53:53
				{auparse.AUDIT_SOCKADDR, `audit(1700000003.000:52): saddr=02000035C0000235000000000000000000`},
				{auparse.AUDIT_PROCTITLE, `audit(1700000003.000:52): proctitle=646967`},
				{auparse.AUDIT_EOE, `audit(1700000003.000:52): `},
			},
			check: func(e *Event) bool {
				return e.EventType == netMonitorTag && e.IPAddress == "192.0.2.53" && e.Port == "53"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProcessMonitor{Events: make(map[int]*Event)}
			dispatched := feedRecords(t, p, tt.records)
			if len(dispatched) != 1 {
				t.Fatalf("expected one dispatch, got %d", len(dispatched))
			}
			if !tt.check(dispatched[0]) {
				t.Fatalf("unexpected dispatched event %+v", dispatched[0])
			}
			if len(p.Events) != 0 {
				t.Fatalf("expected no pending events after EOE, got %d", len(p.Events))
			}
		})
	}
}

func TestPrepareEventDropsIdleEvents(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}
	part := map[string]interface{}{"tags": []string{"netmon"}, "syscall": "sendto"}

	last := 5 * pendingEventWindow
	for sequence := 1; sequence <= last; sequence++ {
		p.PrepareEvent(sequence, part)
	}

	if len(p.Events) > 2*pendingEventWindow+1 {
		t.Fatalf("pending events not bounded: %d", len(p.Events))
	}
	if p.droppedEvents == 0 {
		t.Fatalf("expected dropped events to be counted")
	}
	if _, ok := p.Events[last]; !ok {
		t.Fatalf("the newest event must be kept")
	}
	if _, ok := p.Events[1]; ok {
		t.Fatalf("the oldest event should have been dropped")
	}
}

func TestPrepareEventKeepsActiveEventsDuringSweep(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}
	p.PrepareEvent(1, map[string]interface{}{"tags": []string{"netmon"}, "syscall": "connect"})

	idle := map[string]interface{}{"tags": []string{"netmon"}, "syscall": "sendto"}
	for sequence := 2; sequence <= 2+4*pendingEventWindow; sequence++ {
		p.PrepareEvent(sequence, idle)
		if sequence%1000 == 0 {
			// sequence 1 keeps receiving records, so it is never idle
			p.PrepareEvent(1, map[string]interface{}{})
		}
	}

	if p.droppedEvents == 0 {
		t.Fatalf("expected the sweep to run")
	}
	event, ok := p.Events[1]
	if !ok || event.EventType != netMonitorTag || event.Syscall != "connect" {
		t.Fatalf("an active event lost its data: %+v", event)
	}
}

func TestPrepareEventLateRecordWhileSweeping(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}
	idle := map[string]interface{}{"tags": []string{"netmon"}, "syscall": "sendto"}
	for sequence := 2; sequence <= 2*pendingEventWindow+1; sequence++ {
		p.PrepareEvent(sequence, idle)
	}

	// a late record for an unknown sequence triggers the sweep while it is prepared
	event := p.PrepareEvent(1, map[string]interface{}{"addr": "192.0.2.10", "port": "443"})
	if p.droppedEvents == 0 {
		t.Fatalf("expected the sweep to run")
	}
	if event == nil || event.IPAddress != "192.0.2.10" || p.Events[1] != event {
		t.Fatalf("the event being prepared must survive the sweep, got %+v", event)
	}
}

func TestPrepareEventLosesEventCompletedAfterEviction(t *testing.T) {
	p := &ProcessMonitor{Events: make(map[int]*Event)}
	p.PrepareEvent(1, map[string]interface{}{"tags": []string{"netmon"}, "syscall": "connect"})

	idle := map[string]interface{}{"tags": []string{"netmon"}, "syscall": "sendto"}
	for sequence := 2; sequence <= 2+3*pendingEventWindow; sequence++ {
		p.PrepareEvent(sequence, idle)
	}
	if _, ok := p.Events[1]; ok {
		t.Fatalf("an event idle for longer than the window should be dropped")
	}

	// documented trade-off: the late address alone does not make the event ready
	event := p.PrepareEvent(1, map[string]interface{}{"addr": "192.0.2.10", "port": "443"})
	if isEventReady(event) {
		t.Fatalf("a recreated event without its syscall record must not be dispatched: %+v", event)
	}
}

func TestIsReceiveOverflow(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{syscall.ENOBUFS, true},
		{os.NewSyscallError("recvfrom", syscall.ENOBUFS), true},
		{fmt.Errorf("receive: %w", syscall.ENOBUFS), true},
		{syscall.EBADF, false},
		{errors.New("no buffer space available"), false},
	}
	for _, c := range cases {
		if got := isReceiveOverflow(c.err); got != c.want {
			t.Errorf("isReceiveOverflow(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

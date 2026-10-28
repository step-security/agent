package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestEvent_addRecord(t *testing.T) {
	netEvent := &Event{}
	netEvent.addRecord(map[string]interface{}{"tags": []string{"netmon"}, "syscall": "connect"})
	netEvent.addRecord(map[string]interface{}{"addr": "2.2.2.2", "port": "443"})

	if !isEventReady(netEvent) {
		t.Errorf("Event ready expected")
	}

	fileEvent := &Event{}
	fileEvent.addRecord(map[string]interface{}{"tags": []string{"filemon"}, "syscall": "open"})
	fileEvent.addRecord(map[string]interface{}{"nametype": "CREATE", "name": "file1.txt"})
	fileEvent.addRecord(map[string]interface{}{"cwd": "/dir"})
	fileEvent.addRecord(map[string]interface{}{"argc": "2", "a0": "argv1", "a1": "argv2"})
	// argc that cannot be converted to an int is logged and ignored
	fileEvent.addRecord(map[string]interface{}{"argc": []string{"failed"}})

	if !isEventReady(fileEvent) {
		t.Errorf("Event ready expected")
	}
}

type auditRecord struct {
	msgType auparse.AuditMessageType
	text    string
}

// recordingDispatch collects the events an auditStream dispatches.
type recordingDispatch struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingDispatch) dispatch(event *Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, *event)
}

func (r *recordingDispatch) dispatched() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// countingStream wraps an auditStream and counts every delivered event.
type countingStream struct {
	*auditStream
	delivered atomic.Int64
}

func (c *countingStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	c.delivered.Add(1)
	c.auditStream.ReassemblyComplete(msgs)
}

func newTestReassembler(t *testing.T, maxInFlight int, timeout time.Duration) (*libaudit.Reassembler, *countingStream, *recordingDispatch, *ProcessMonitor) {
	t.Helper()
	p := &ProcessMonitor{}
	rec := &recordingDispatch{}
	stream := &countingStream{auditStream: &auditStream{monitor: p, dispatch: rec.dispatch}}
	r, err := libaudit.NewReassembler(maxInFlight, timeout, stream)
	if err != nil {
		t.Fatalf("new reassembler: %v", err)
	}
	return r, stream, rec, p
}

func pushRecords(t *testing.T, r *libaudit.Reassembler, records []auditRecord) {
	t.Helper()
	for _, rec := range records {
		if err := r.Push(rec.msgType, []byte(rec.text)); err != nil {
			t.Fatalf("push %v: %v", rec.msgType, err)
		}
	}
}

func syscallRecord(seq, syscallNr int, comm, exe, key string) auditRecord {
	return auditRecord{auparse.AUDIT_SYSCALL, fmt.Sprintf(`audit(1700000000.000:%d): arch=c000003e syscall=%d success=yes exit=0 a0=3 a1=7f00 a2=10 a3=0 items=1 ppid=1 pid=%d auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm="%s" exe="%s" key="%s"`, seq, syscallNr, 100+seq, comm, exe, key)}
}

func proctitleRecord(seq int) auditRecord {
	return auditRecord{auparse.AUDIT_PROCTITLE, fmt.Sprintf(`audit(1700000000.000:%d): proctitle=7465737400`, seq)}
}

func eoeRecord(seq int) auditRecord {
	return auditRecord{auparse.AUDIT_EOE, fmt.Sprintf(`audit(1700000000.000:%d): `, seq)}
}

func TestReassemblyDispatchesDetectionsOnce(t *testing.T) {
	tests := []struct {
		name    string
		records []auditRecord
		want    func(Event) bool
	}{
		{
			name: "connect",
			records: []auditRecord{
				syscallRecord(43, 42, "curl", "/usr/bin/curl", "netmon"),
				// 192.0.2.10:443
				{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:43): saddr=020001BBC000020A0000000000000000`},
				proctitleRecord(43),
				eoeRecord(43),
			},
			want: func(e Event) bool {
				return e.EventType == netMonitorTag && e.Syscall == "connect" && e.IPAddress == "192.0.2.10" && e.Port == "443" &&
					e.Pid == "143" && e.PPid == "1" && e.Exe == "/usr/bin/curl" && e.Euid == "1001" && e.Status == "success" &&
					e.Timestamp.Equal(time.Unix(1700000000, 0))
			},
		},
		{
			name: "sendto with an address",
			records: []auditRecord{
				syscallRecord(52, 44, "dig", "/usr/bin/dig", "netmon"),
				// 192.0.2.53:53
				{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:52): saddr=02000035C0000235000000000000000000`},
				proctitleRecord(52),
				eoeRecord(52),
			},
			want: func(e Event) bool {
				return e.EventType == netMonitorTag && e.IPAddress == "192.0.2.53" && e.Port == "53"
			},
		},
		{
			name: "process start",
			records: []auditRecord{
				syscallRecord(50, 59, "ls", "/usr/bin/ls", "procmon"),
				{auparse.AUDIT_EXECVE, `audit(1700000000.000:50): argc=2 a0="ls" a1="-l"`},
				{auparse.AUDIT_CWD, `audit(1700000000.000:50): cwd="/home/runner/work"`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:50): item=0 name="/usr/bin/ls" inode=10 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				proctitleRecord(50),
				eoeRecord(50),
			},
			want: func(e Event) bool {
				return e.EventType == processMonitorTag && reflect.DeepEqual(e.ProcessArguments, []string{"ls", "-l"}) && e.Path == "/home/runner/work" &&
					e.Pid == "150" && e.Exe == "/usr/bin/ls"
			},
		},
		{
			name: "file write",
			records: []auditRecord{
				syscallRecord(51, 257, "bash", "/usr/bin/bash", "filemon"),
				{auparse.AUDIT_CWD, `audit(1700000000.000:51): cwd="/home/runner/work/repo"`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:51): item=1 name="out.txt" inode=11 dev=08:01 mode=0100644 ouid=1001 ogid=1001 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				proctitleRecord(51),
				eoeRecord(51),
			},
			want: func(e Event) bool {
				return e.EventType == fileMonitorTag && e.FileName == "out.txt" && e.Path == "/home/runner/work/repo"
			},
		},
		{
			name: "connect over IPv6",
			records: []auditRecord{
				syscallRecord(54, 42, "curl", "/usr/bin/curl", "netmon"),
				// [2001:db8::1]:443
				{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:54): saddr=0A0001BB0000000020010DB800000000000000000000000100000000`},
				proctitleRecord(54),
				eoeRecord(54),
			},
			want: func(e Event) bool {
				return e.EventType == netMonitorTag && e.IPAddress == "2001:db8::1" && e.Port == "443"
			},
		},
		{
			// rename has PARENT, DELETE and CREATE paths; the first qualifying one is kept
			name: "rename keeps the source file",
			records: []auditRecord{
				syscallRecord(53, 82, "mv", "/usr/bin/mv", "filemon"),
				{auparse.AUDIT_CWD, `audit(1700000000.000:53): cwd="/home/runner/work/repo"`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:53): item=0 name="/home/runner/work/repo" inode=5 dev=08:01 mode=040755 ouid=1001 ogid=1001 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:53): item=1 name="/home/runner/work/repo" inode=5 dev=08:01 mode=040755 ouid=1001 ogid=1001 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:53): item=2 name="Dockerfile" inode=12 dev=08:01 mode=0100644 ouid=1001 ogid=1001 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				{auparse.AUDIT_PATH, `audit(1700000000.000:53): item=3 name="tmpfile" inode=12 dev=08:01 mode=0100644 ouid=1001 ogid=1001 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`},
				proctitleRecord(53),
				eoeRecord(53),
			},
			want: func(e Event) bool {
				return e.EventType == fileMonitorTag && e.FileName == "Dockerfile" && e.Path == "/home/runner/work/repo"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)
			pushRecords(t, r, tt.records)

			// delivered when the event completes, before any timeout or flush
			got := rec.dispatched()
			if len(got) != 1 {
				t.Fatalf("expected one dispatch, got %d", len(got))
			}
			if !tt.want(got[0]) {
				t.Fatalf("unexpected dispatched event %+v", got[0])
			}
			r.Close()
			if again := rec.dispatched(); len(again) != 1 {
				t.Fatalf("the final flush must not dispatch again, got %d", len(again))
			}
		})
	}
}

func TestReassemblyDropsSendWithoutAddress(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// send() on a connected socket: sendto with no SOCKADDR record
	pushRecords(t, r, []auditRecord{syscallRecord(42, 44, "python3", "/usr/bin/python3.12", "netmon"), proctitleRecord(42), eoeRecord(42)})

	if stream.delivered.Load() != 1 {
		t.Fatalf("expected the event to be delivered once, got %d", stream.delivered.Load())
	}
	if got := rec.dispatched(); len(got) != 0 {
		t.Fatalf("a send without an address must not be dispatched, got %+v", got)
	}
}

func TestReassemblyDoesNotKeepIncompleteEvents(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// records that never complete (no PROCTITLE or EOE) must not pile up
	const events = 10000
	for seq := 1; seq <= events; seq++ {
		pushRecords(t, r, []auditRecord{syscallRecord(seq, 44, "python3", "/usr/bin/python3.12", "netmon")})
	}

	// 50 is Auditbeat's default; compared as a literal so a change to the limit is caught
	if inFlight := events - stream.delivered.Load(); inFlight > 50 {
		t.Fatalf("expected at most 50 events in flight, got %d", inFlight)
	}
	if got := rec.dispatched(); len(got) != 0 {
		t.Fatalf("incomplete sends must not be dispatched, got %d", len(got))
	}
}

func TestReassemblyGivesUpOnEventsAfterTimeout(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, 50*time.Millisecond)

	// a connect whose last records never arrive
	pushRecords(t, r, []auditRecord{
		syscallRecord(60, 42, "curl", "/usr/bin/curl", "netmon"),
		{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:60): saddr=020001BBC000020A0000000000000000`},
	})
	if stream.delivered.Load() != 0 {
		t.Fatalf("event delivered before it completed or timed out")
	}

	time.Sleep(100 * time.Millisecond)
	if err := r.Maintain(); err != nil {
		t.Fatalf("maintain: %v", err)
	}

	if stream.delivered.Load() != 1 {
		t.Fatalf("expected the timed out event to be delivered, got %d", stream.delivered.Load())
	}
	if got := rec.dispatched(); len(got) != 1 || got[0].IPAddress != "192.0.2.10" {
		t.Fatalf("expected the connect to be dispatched with what arrived, got %+v", got)
	}
}

func TestReassemblyCountsLostEvents(t *testing.T) {
	r, _, _, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// sequences 71 to 74 never arrive
	pushRecords(t, r, []auditRecord{syscallRecord(70, 42, "curl", "/usr/bin/curl", "netmon"), proctitleRecord(70)})
	pushRecords(t, r, []auditRecord{syscallRecord(75, 42, "curl", "/usr/bin/curl", "netmon"), proctitleRecord(75)})

	if got := p.sequenceGaps.Load(); got != 4 {
		t.Fatalf("expected a gap of 4, got %d", got)
	}
}

func TestEventsLostIgnoresImpossibleGaps(t *testing.T) {
	p := &ProcessMonitor{}
	stream := &auditStream{monitor: p, dispatch: func(*Event) {}}

	// what go-libaudit v2.3.2 reports when a record arrives after its event was given up
	stream.EventsLost(int(^uint32(0)))
	stream.EventsLost(0)
	if got := p.sequenceGaps.Load(); got != 0 {
		t.Fatalf("impossible gaps must be ignored, got %d", got)
	}

	stream.EventsLost(3)
	if got := p.sequenceGaps.Load(); got != 3 {
		t.Fatalf("expected a gap of 3, got %d", got)
	}
}

func TestReassemblyCountsRecordFieldErrors(t *testing.T) {
	r, _, rec, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// a valid header with an address that cannot be decoded
	pushRecords(t, r, []auditRecord{
		syscallRecord(90, 42, "curl", "/usr/bin/curl", "netmon"),
		{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:90): saddr=ZZZZ`},
		proctitleRecord(90),
	})

	if got := p.recordErrors.Load(); got != 1 {
		t.Fatalf("expected one record with unparsed fields, got %d", got)
	}
	if got := rec.dispatched(); len(got) != 0 {
		t.Fatalf("a connect without an address must not be dispatched, got %+v", got)
	}
}

func TestReassemblyHandlesShortSocketAddresses(t *testing.T) {
	// go-libaudit before v2.6.0 panicked on these (elastic/go-libaudit#152)
	// too short for the family, for AF_INET and for AF_INET6
	for _, saddr := range []string{"ZZ", "02", "", "0200", "02000050", "0A00", "0A0001BB"} {
		t.Run(fmt.Sprintf("saddr=%q", saddr), func(t *testing.T) {
			r, _, rec, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)
			pushRecords(t, r, []auditRecord{
				syscallRecord(91, 42, "curl", "/usr/bin/curl", "netmon"),
				{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:91): saddr=` + saddr},
				proctitleRecord(91),
			})
			if got := rec.dispatched(); len(got) != 0 {
				t.Fatalf("a connect without a usable address must not be dispatched, got %+v", got)
			}
			if got := p.recordErrors.Load(); got != 1 {
				t.Fatalf("expected the record to be counted as not parsed, got %d", got)
			}
		})
	}
}

func TestNoteLossLogsOnPowersOfTwo(t *testing.T) {
	var counter atomic.Int64
	var logged []int64
	for i := 0; i < 20; i++ {
		if noteLoss(&counter, 1, "test") {
			logged = append(logged, counter.Load())
		}
	}
	want := []int64{1, 2, 4, 8, 16}
	if fmt.Sprint(logged) != fmt.Sprint(want) {
		t.Fatalf("logged at %v, want %v", logged, want)
	}

	// a batch that crosses a power of two logs once
	if !noteLoss(&counter, 20, "test") {
		t.Fatalf("expected a log when the total goes from 20 to 40")
	}
}

func TestNoteReceiveError(t *testing.T) {
	cases := []struct {
		err          error
		wantOverflow int64
		wantOther    int64
	}{
		{syscall.ENOBUFS, 1, 0},
		{os.NewSyscallError("recvfrom", syscall.ENOBUFS), 1, 0},
		{fmt.Errorf("receive: %w", syscall.ENOBUFS), 1, 0},
		{syscall.EINVAL, 0, 1},
		{errors.New("no buffer space available"), 0, 1},
	}
	for _, c := range cases {
		p := &ProcessMonitor{}
		p.noteReceiveError(c.err)
		if p.receiveOverflow.Load() != c.wantOverflow || p.receiveErrors.Load() != c.wantOther {
			t.Errorf("noteReceiveError(%v): overflow=%d other=%d, want %d %d", c.err, p.receiveOverflow.Load(), p.receiveErrors.Load(), c.wantOverflow, c.wantOther)
		}
	}
}

func TestHasDetectionRecord(t *testing.T) {
	msg := func(typ auparse.AuditMessageType) *auparse.AuditMessage {
		return &auparse.AuditMessage{RecordType: typ}
	}
	tests := []struct {
		name string
		msgs []*auparse.AuditMessage
		want bool
	}{
		{"send without address", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL), msg(auparse.AUDIT_PROCTITLE), msg(auparse.AUDIT_EOE)}, false},
		{"syscall only", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL)}, false},
		{"empty", nil, false},
		{"connect", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL), msg(auparse.AUDIT_SOCKADDR), msg(auparse.AUDIT_PROCTITLE)}, true},
		{"execve", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL), msg(auparse.AUDIT_EXECVE), msg(auparse.AUDIT_CWD)}, true},
		{"file", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL), msg(auparse.AUDIT_CWD), msg(auparse.AUDIT_PATH)}, true},
		{"other record type", []*auparse.AuditMessage{msg(auparse.AUDIT_SYSCALL), msg(auparse.AUDIT_CONFIG_CHANGE)}, true},
	}
	for _, tt := range tests {
		if got := hasDetectionRecord(tt.msgs); got != tt.want {
			t.Errorf("%s: hasDetectionRecord() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Events that are not parsed must be ones that full parsing would not have
// dispatched either.
func TestEventsWithoutDetectionRecordsAreNeverReady(t *testing.T) {
	events := [][]auditRecord{
		{syscallRecord(60, 44, "python3", "/usr/bin/python3.12", "netmon"), proctitleRecord(60), eoeRecord(60)},
		{syscallRecord(61, 46, "node", "/usr/bin/node", "netmon"), proctitleRecord(61)},
		{syscallRecord(62, 42, "curl", "/usr/bin/curl", "netmon")},
		{syscallRecord(63, 59, "bash", "/usr/bin/bash", "procmon"), proctitleRecord(63)},
		{syscallRecord(64, 257, "cp", "/usr/bin/cp", "filemon"), proctitleRecord(64)},
		// values the kernel hex-encodes because they contain spaces
		{{auparse.AUDIT_SYSCALL, `audit(1700000000.000:65): arch=c000003e syscall=44 success=yes exit=1 a0=3 a1=7f00 a2=1 a3=0 items=0 ppid=1 pid=165 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=4294967295 comm=6164647220616464723D312E322E332E34 exe="/tmp/x" key="netmon"`},
			{auparse.AUDIT_PROCTITLE, `audit(1700000000.000:65): proctitle=6E6320616464723D312E322E332E3420706F72743D343433`}},
	}
	for i, records := range events {
		var msgs []*auparse.AuditMessage
		for _, rec := range records {
			msg, err := auparse.Parse(rec.msgType, rec.text)
			if err != nil {
				t.Fatalf("event %d: parse %v: %v", i, rec.msgType, err)
			}
			msgs = append(msgs, msg)
		}
		if hasDetectionRecord(msgs) {
			t.Fatalf("event %d: expected no detection record", i)
		}
		event := &Event{}
		for _, msg := range msgs {
			eventMap := msg.ToMapStr()
			if parseErr, found := eventMap["error"]; found {
				t.Fatalf("event %d: %v record not parsed: %v", i, msg.RecordType, parseErr)
			}
			event.addRecord(eventMap)
		}
		if isEventReady(event) {
			t.Errorf("event %d: fully parsed event is ready: %+v", i, event)
		}
	}
}

func TestReassemblySkipsParsingEventsWithoutDetectionRecords(t *testing.T) {
	r, stream, rec, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// an arch that cannot be decoded is a field error, but only if parsed
	pushRecords(t, r, []auditRecord{
		{auparse.AUDIT_SYSCALL, `audit(1700000000.000:70): arch=zz syscall=44 success=yes exit=1 a0=3 a1=7f00 a2=1 a3=0 items=0 ppid=1 pid=170 comm="python3" exe="/usr/bin/python3.12" key="netmon"`},
		proctitleRecord(70),
		eoeRecord(70),
	})

	if stream.delivered.Load() != 1 {
		t.Fatalf("expected the event to be delivered once, got %d", stream.delivered.Load())
	}
	if got := p.recordErrors.Load(); got != 0 {
		t.Fatalf("expected the event not to be parsed, got %d field errors", got)
	}
	if got := rec.dispatched(); len(got) != 0 {
		t.Fatalf("expected nothing dispatched, got %+v", got)
	}
}

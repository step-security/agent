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

// pushRecords passes records to the reassembler the way receive does.
func pushRecords(t *testing.T, r *libaudit.Reassembler, stream *countingStream, records []auditRecord) {
	t.Helper()
	for _, rec := range records {
		msg, err := auparse.Parse(rec.msgType, rec.text)
		if err != nil {
			t.Fatalf("parse %v: %v", rec.msgType, err)
		}
		stream.push(r, msg)
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
			r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)
			pushRecords(t, r, stream, tt.records)

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

func TestReassemblySkipsRecordsOutsideSyscallEvents(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	pushRecords(t, r, stream, []auditRecord{
		// a BPF program unload, logged on its own, with no record that completes it
		{auparse.AUDIT_BPF, `audit(1700000000.000:30): prog-id=12 op=UNLOAD`},
		// a BPF record logged during an audited syscall, before its SYSCALL record
		{auparse.AUDIT_BPF, `audit(1700000000.000:31): prog-id=13 op=LOAD`},
		syscallRecord(31, 42, "curl", "/usr/bin/curl", "netmon"),
		{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:31): saddr=020001BBC000020A0000000000000000`},
		proctitleRecord(31),
		eoeRecord(31),
		syscallRecord(32, 59, "ls", "/usr/bin/ls", "procmon"),
		{auparse.AUDIT_EXECVE, `audit(1700000000.000:32): argc=1 a0="ls"`},
		{auparse.AUDIT_CWD, `audit(1700000000.000:32): cwd="/home/runner/work"`},
		proctitleRecord(32),
		eoeRecord(32),
	})

	// both are delivered as they complete, not held behind the BPF record
	got := rec.dispatched()
	if len(got) != 2 || got[0].IPAddress != "192.0.2.10" || got[1].Exe != "/usr/bin/ls" {
		t.Fatalf("expected the connect and the process start right away, got %+v", got)
	}
	if delivered := stream.delivered.Load(); delivered != 2 {
		t.Fatalf("records outside syscall events must not reach the reassembler, %d events delivered", delivered)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.syscallEvents) != 0 {
		t.Fatalf("delivered events must be forgotten, %d left", len(stream.syscallEvents))
	}
}

func TestReassemblyCompletesOnEOEWithoutProctitle(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	pushRecords(t, r, stream, []auditRecord{
		syscallRecord(34, 42, "curl", "/usr/bin/curl", "netmon"),
		{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:34): saddr=020001BBC000020A0000000000000000`},
		eoeRecord(34),
	})

	if got := rec.dispatched(); len(got) != 1 || got[0].IPAddress != "192.0.2.10" {
		t.Fatalf("expected the connect to be dispatched on its EOE, got %+v", got)
	}
}

func TestReassemblyDropsRecordsAfterTheEventIsDelivered(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, 50*time.Millisecond)

	// a connect given up before its last records arrive
	pushRecords(t, r, stream, []auditRecord{
		syscallRecord(33, 42, "curl", "/usr/bin/curl", "netmon"),
		{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:33): saddr=020001BBC000020A0000000000000000`},
	})
	time.Sleep(100 * time.Millisecond)
	if err := r.Maintain(); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	pushRecords(t, r, stream, []auditRecord{proctitleRecord(33), eoeRecord(33)})
	r.Close()

	if delivered := stream.delivered.Load(); delivered != 1 {
		t.Fatalf("late records must not start a new event, %d events delivered", delivered)
	}
	if got := rec.dispatched(); len(got) != 1 {
		t.Fatalf("expected the connect to be dispatched once, got %+v", got)
	}
}

// blockingStream holds the delivery of one event until released.
type blockingStream struct {
	*auditStream
	seq      uint32
	entered  chan struct{}
	release  chan struct{}
	enterOne sync.Once
}

func (b *blockingStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if msgs[0].Sequence == b.seq {
		b.enterOne.Do(func() { close(b.entered) })
		<-b.release
	}
	b.auditStream.ReassemblyComplete(msgs)
}

func TestLateRecordWaitsForTheEventToBeGivenUp(t *testing.T) {
	rec := &recordingDispatch{}
	stream := &auditStream{monitor: &ProcessMonitor{}, dispatch: rec.dispatch}
	blocking := &blockingStream{auditStream: stream, seq: 40, entered: make(chan struct{}), release: make(chan struct{})}
	r, err := libaudit.NewReassembler(reassemblerMaxInFlight, 50*time.Millisecond, blocking)
	if err != nil {
		t.Fatalf("new reassembler: %v", err)
	}
	push := func(records ...auditRecord) {
		for _, record := range records {
			msg, err := auparse.Parse(record.msgType, record.text)
			if err != nil {
				t.Errorf("parse %v: %v", record.msgType, err)
				return
			}
			stream.push(r, msg)
		}
	}

	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(blocking.release) }) }
	maintained := make(chan struct{})
	t.Cleanup(func() {
		releaseCallback()
		<-maintained
	})

	// a connect whose address arrives just as it is given up
	push(syscallRecord(40, 42, "curl", "/usr/bin/curl", "netmon"))
	time.Sleep(100 * time.Millisecond)
	go func() {
		defer close(maintained)
		stream.maintain(r)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("maintenance did not give up the event")
	}

	pushed := make(chan struct{})
	go func() {
		push(auditRecord{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:40): saddr=020001BBC000020A0000000000000000`})
		close(pushed)
	}()
	select {
	case <-pushed:
		t.Fatalf("a record was pushed while its event was being given up")
	case <-time.After(100 * time.Millisecond):
	}
	releaseCallback()
	select {
	case <-pushed:
	case <-time.After(5 * time.Second):
		t.Fatalf("the late record was not pushed after the event was given up")
	}

	// the late record did not start a new event that holds this one back
	push(
		syscallRecord(41, 42, "curl", "/usr/bin/curl", "netmon"),
		auditRecord{auparse.AUDIT_SOCKADDR, `audit(1700000000.000:41): saddr=020001BBC000020A0000000000000000`},
		proctitleRecord(41),
	)
	got := rec.dispatched()
	if len(got) != 1 || got[0].Pid != "141" {
		t.Fatalf("expected only the second connect to be dispatched, right away, got %+v", got)
	}
}

func TestSyscallEventsAreBounded(t *testing.T) {
	r, stream, _, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	for seq := 1; seq <= 10000; seq++ {
		pushRecords(t, r, stream, []auditRecord{syscallRecord(seq, 44, "python3", "/usr/bin/python3.12", "netmon")})
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()
	// at most the events the reassembler holds, plus the one being added
	if n := len(stream.syscallEvents); n > reassemblerMaxInFlight+1 {
		t.Fatalf("expected at most %d tracked events, got %d", reassemblerMaxInFlight+1, n)
	}
}

func TestReassemblyDropsSendWithoutAddress(t *testing.T) {
	r, stream, rec, _ := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// send() on a connected socket: sendto with no SOCKADDR record
	pushRecords(t, r, stream, []auditRecord{syscallRecord(42, 44, "python3", "/usr/bin/python3.12", "netmon"), proctitleRecord(42), eoeRecord(42)})

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
		pushRecords(t, r, stream, []auditRecord{syscallRecord(seq, 44, "python3", "/usr/bin/python3.12", "netmon")})
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
	pushRecords(t, r, stream, []auditRecord{
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
	r, stream, _, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// sequences 71 to 74 never arrive
	pushRecords(t, r, stream, []auditRecord{syscallRecord(70, 42, "curl", "/usr/bin/curl", "netmon"), proctitleRecord(70)})
	pushRecords(t, r, stream, []auditRecord{syscallRecord(75, 42, "curl", "/usr/bin/curl", "netmon"), proctitleRecord(75)})

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
	r, stream, rec, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)

	// a valid header with an address that cannot be decoded
	pushRecords(t, r, stream, []auditRecord{
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
			r, stream, rec, p := newTestReassembler(t, reassemblerMaxInFlight, reassemblerTimeout)
			pushRecords(t, r, stream, []auditRecord{
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

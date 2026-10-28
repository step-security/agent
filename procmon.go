package main

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
)

const (
	netMonitorTag     = "netmon"
	fileMonitorTag    = "filemon"
	processMonitorTag = "procmon"
)

// Audit records are grouped into events by go-libaudit's reassembler, with the
// same limits Auditbeat uses by default: at most 50 events in flight, and an
// event without its last record is given up after 2 seconds.
const (
	reassemblerMaxInFlight = 50
	reassemblerTimeout     = 2 * time.Second
	reassemblerMaintain    = 500 * time.Millisecond
)

// Kernel audit queue settings, from Auditbeat's defaults. The kernel's own
// defaults (64 records, 60 second wait) make audited syscalls sleep whenever
// the agent falls behind, which slows the job instead of dropping records.
const (
	auditBacklogLimit       = 8192
	auditFallbackRateLimit  = 5000 // only when the wait time cannot be set to 0
	kernelLostCheckInterval = 15 * time.Second
)

type ProcessMonitor struct {
	CorrelationId         string
	Repo                  string
	ApiClient             *ApiClient
	DNSProxy              *DNSProxy
	WorkingDirectory      string
	DisableFileMonitoring bool

	// dispatchEvent replaces the event handler in tests
	dispatchEvent func(*Event)

	sequenceGaps    atomic.Int64
	receiveOverflow atomic.Int64
	receiveErrors   atomic.Int64
	invalidRecords  atomic.Int64
	recordErrors    atomic.Int64
	kernelLost      atomic.Int64
}

type Process struct {
	PID              string
	PPid             string
	Exe              string
	Container        string // container that started this process
	WorkingDirectory string
	Arguments        []string
	Scenario         string // npm publish, dotnet push are scenarios
	Timestamp        string
}

type Event struct {
	FileName         string
	Path             string
	Syscall          string
	Exe              string
	IPAddress        string
	Port             string
	Pid              string
	ProcessArguments []string
	PPid             string
	Euid             string
	Timestamp        time.Time
	EventType        string
	Status           string
}

func (event *Event) addRecord(eventMap map[string]interface{}) {
	// Tags
	value, found := eventMap["tags"]

	if found {
		tags := value.([]string)
		for _, tag := range tags {
			event.EventType = tag
			event.Syscall = getValue("syscall", eventMap)
			event.Exe = getValue("exe", eventMap)
			event.Pid = getValue("pid", eventMap)
			event.PPid = getValue("ppid", eventMap)
			event.Euid = getValue("euid", eventMap)
			timestamp, err := time.Parse("2006-01-02 15:04:05.999999999 +0000 UTC", getValue("@timestamp", eventMap))
			if err != nil {
				timestamp = time.Now().UTC()
			}
			event.Timestamp = timestamp
			event.Status = getValue("result", eventMap)
		}
	}

	// Current working directory
	_, found = eventMap["cwd"]
	if found {
		event.Path = getValue("cwd", eventMap)
	}

	// Connect
	_, found = eventMap["addr"]
	if found {
		event.IPAddress = getValue("addr", eventMap)
		event.Port = getValue("port", eventMap)
	}

	// Process start
	argc, found := eventMap["argc"]

	if found {
		argCountStr := fmt.Sprintf("%v", argc)
		argCount, err := strconv.Atoi(argCountStr)
		if err != nil {
			WriteLog(fmt.Sprintf("could not parse argc:%v", argc))
		}
		for i := 0; i < argCount; i++ {
			event.ProcessArguments = append(event.ProcessArguments, fmt.Sprintf("%v", eventMap[fmt.Sprintf("a%d", i)]))
		}
	}

	// File operation
	nameType, found := eventMap["nametype"]

	if found {
		nameTypeStr := fmt.Sprintf("%v", nameType)
		// the first qualifying PATH wins, as when events were dispatched on it
		if (nameTypeStr == "DELETE" || nameTypeStr == "CREATE" || nameTypeStr == "NORMAL") && event.FileName == "" {
			event.FileName = getValue("name", eventMap)
		}
	}
}

func getValue(key string, eventMap map[string]interface{}) string {
	val, found := eventMap[key]
	if found {
		return fmt.Sprintf("%v", val)
	}

	return ""
}

// auditStream receives complete events from the reassembler and dispatches
// the ones the event handler uses. Every event is delivered once, including
// incomplete ones that are evicted, so nothing is kept after delivery.
type auditStream struct {
	monitor  *ProcessMonitor
	dispatch func(*Event)
}

func (s *auditStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event := &Event{}
	for _, msg := range msgs {
		eventMap := msg.ToMapStr()
		if parseErr, found := eventMap["error"]; found {
			noteLoss(&s.monitor.recordErrors, 1, fmt.Sprintf("audit record fields not parsed: %v", parseErr))
		}
		event.addRecord(eventMap)
	}
	if isEventReady(event) {
		s.dispatch(event)
	}
}

// EventsLost is called for gaps in the audit sequence numbers. A gap is not
// always a loss, since record types this agent skips use sequence numbers too.
func (s *auditStream) EventsLost(count int) {
	// go-libaudit v2.3.2 underflows when a record arrives after its event was
	// given up, which shows up as a huge count
	if count <= 0 || count > 1<<24 {
		return
	}
	noteLoss(&s.monitor.sequenceGaps, int64(count), "gaps in audit sequence numbers")
}

// noteReceiveError counts a failed receive. A full netlink socket (ENOBUFS)
// means the kernel dropped messages; the socket stays usable either way.
func (p *ProcessMonitor) noteReceiveError(err error) {
	if errors.Is(err, syscall.ENOBUFS) {
		noteLoss(&p.receiveOverflow, 1, "audit netlink buffer overflowed, kernel dropped messages")
		return
	}
	noteLoss(&p.receiveErrors, 1, fmt.Sprintf("audit receive error: %v", err))
}

// noteLoss adds n to the counter and logs when the total reaches the next
// power of two, so a sustained loss does not flood the log. It reports whether
// it logged.
func noteLoss(counter *atomic.Int64, n int64, what string) bool {
	total := counter.Add(n)
	if bits.Len64(uint64(total)) == bits.Len64(uint64(total-n)) {
		return false
	}
	WriteLog(fmt.Sprintf("[procmon] %s, total=%d", what, total))
	return true
}

func isEventReady(event *Event) bool {
	switch event.EventType {
	case netMonitorTag:
		if event.IPAddress != "" && event.Port != "" {
			return true
		}
	case fileMonitorTag:
		if event.FileName != "" && event.Path != "" {
			return true
		}
	case processMonitorTag:
		if len(event.ProcessArguments) > 0 && event.Path != "" {
			return true
		}
	}
	return false
}

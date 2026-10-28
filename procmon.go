package main

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
)

const (
	netMonitorTag     = "netmon"
	fileMonitorTag    = "filemon"
	processMonitorTag = "procmon"
)

// pendingEventWindow is how many audit records may arrive without touching an
// event before it is dropped. Events are retired on their EOE record; this
// catches the ones that never get one, such as single-record events. It also
// bounds the map: at most this many events can have been touched recently.
// An event whose remaining records arrive after it was dropped is lost, since
// the late records alone do not make it ready.
const pendingEventWindow = 8192

type ProcessMonitor struct {
	CorrelationId         string
	Repo                  string
	ApiClient             *ApiClient
	DNSProxy              *DNSProxy
	WorkingDirectory      string
	DisableFileMonitoring bool
	Events                map[int]*Event
	mutex                 sync.RWMutex

	records         int64
	droppedEvents   int
	receiveOverflow int
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
	FileName          string
	Path              string
	Syscall           string
	Exe               string
	IPAddress         string
	Port              string
	Pid               string
	ProcessArguments  []string
	PPid              string
	Euid              string
	Timestamp         time.Time
	EventType         string
	Status            string
	SentForProcessing bool
	lastRecord        int64
}

func (p *ProcessMonitor) PrepareEvent(sequence int, eventMap map[string]interface{}) *Event {
	p.mutex.Lock()
	p.records++
	event, found := p.Events[sequence]
	if !found {
		event = &Event{}
		p.Events[sequence] = event
	}
	// refreshed before the sweep, so the event being prepared is never dropped
	event.lastRecord = p.records
	if !found && len(p.Events) > 2*pendingEventWindow {
		p.dropIdleEventsLocked()
	}

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
		if nameTypeStr == "DELETE" || nameTypeStr == "CREATE" || nameTypeStr == "NORMAL" {
			event.FileName = getValue("name", eventMap)
		}
	}

	p.mutex.Unlock()
	return event
}

func getValue(key string, eventMap map[string]interface{}) string {
	val, found := eventMap[key]
	if found {
		return fmt.Sprintf("%v", val)
	}

	return ""
}

// handleRecord adds one audit record to its event and returns the event once
// it is ready to dispatch. The EOE record ends a multi-record event, so the
// event is removed then.
func (p *ProcessMonitor) handleRecord(msgType auparse.AuditMessageType, message *auparse.AuditMessage) *Event {
	sequence := int(message.Sequence)
	if msgType == auparse.AUDIT_EOE {
		p.retireEvent(sequence)
		return nil
	}

	event := p.PrepareEvent(sequence, message.ToMapStr())
	if !isEventReady(event) {
		return nil
	}
	p.markEventSent(event)
	return event
}

// retireEvent removes a sequence once its EOE record arrives. Handlers keep
// their own pointer, so an event already dispatched is unaffected.
func (p *ProcessMonitor) retireEvent(sequence int) {
	p.mutex.Lock()
	delete(p.Events, sequence)
	p.mutex.Unlock()
}

func (p *ProcessMonitor) dropIdleEventsLocked() {
	dropped := 0
	for sequence, event := range p.Events {
		if event.lastRecord <= p.records-pendingEventWindow {
			delete(p.Events, sequence)
			dropped++
		}
	}
	p.droppedEvents += dropped
	WriteLog(fmt.Sprintf("[procmon] dropped %d audit events without EOE, total=%d", dropped, p.droppedEvents))
}

// isReceiveOverflow reports whether the kernel dropped audit messages because
// the netlink socket was full. The socket stays usable, so receiving continues.
func isReceiveOverflow(err error) bool {
	return errors.Is(err, syscall.ENOBUFS)
}

func (p *ProcessMonitor) noteReceiveOverflow() {
	p.receiveOverflow++
	// log on 1, 2, 4, 8, ... so a sustained overflow does not flood the log
	if p.receiveOverflow&(p.receiveOverflow-1) == 0 {
		WriteLog(fmt.Sprintf("[procmon] audit messages lost, netlink buffer full, total=%d", p.receiveOverflow))
	}
}

func (p *ProcessMonitor) markEventSent(event *Event) {
	p.mutex.Lock()
	event.SentForProcessing = true
	p.mutex.Unlock()
}

func isEventReady(event *Event) bool {
	if event.SentForProcessing {
		return false
	}

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

package main

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

const (
	netMonitorTag     = "netmon"
	fileMonitorTag    = "filemon"
	processMonitorTag = "procmon"
)

type ProcessMonitor struct {
	CorrelationId    string
	Repo             string
	ApiClient        *ApiClient
	DNSProxy         *DNSProxy
	WorkingDirectory string
	Events           map[int]*Event
	mutex            sync.RWMutex
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
	Timestamp         time.Time
	EventType         string
	Status            string
	SentForProcessing bool
}

func (p *ProcessMonitor) PrepareEvent(sequence int, eventMap map[string]interface{}) {
	p.mutex.Lock()
	_, found := p.Events[sequence]
	if !found {
		p.Events[sequence] = &Event{}
	}

	// Tags
	value, found := eventMap["tags"]

	if found {
		tags := value.([]string)
		for _, tag := range tags {
			p.Events[sequence].EventType = tag
			p.Events[sequence].Syscall = getValue("syscall", eventMap)
			p.Events[sequence].Exe = getValue("exe", eventMap)
			p.Events[sequence].Pid = getValue("pid", eventMap)
			p.Events[sequence].PPid = getValue("ppid", eventMap)
			timestamp, err := time.Parse("2006-01-02 15:04:05.999999999 +0000 UTC", getValue("@timestamp", eventMap))
			if err != nil {
				timestamp = time.Now().UTC()
			}
			p.Events[sequence].Timestamp = timestamp
			p.Events[sequence].Status = getValue("result", eventMap)
		}
	}

	// Current working directory
	_, found = eventMap["cwd"]
	if found {
		p.Events[sequence].Path = getValue("cwd", eventMap)
	}

	// Connect
	_, found = eventMap["addr"]
	if found {
		p.Events[sequence].IPAddress = getValue("addr", eventMap)
		p.Events[sequence].Port = getValue("port", eventMap)
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
			p.Events[sequence].ProcessArguments = append(p.Events[sequence].ProcessArguments, fmt.Sprintf("%v", eventMap[fmt.Sprintf("a%d", i)]))
		}
	}

	// File operation
	nameType, found := eventMap["nametype"]

	if found {
		nameTypeStr := fmt.Sprintf("%v", nameType)
		if nameTypeStr == "DELETE" || nameTypeStr == "CREATE" || nameTypeStr == "NORMAL" {
			p.Events[sequence].FileName = getValue("name", eventMap)
		}
	}

	p.mutex.Unlock()
}

func getValue(key string, eventMap map[string]interface{}) string {
	val, found := eventMap[key]
	if found {
		return fmt.Sprintf("%v", val)
	}

	return ""
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

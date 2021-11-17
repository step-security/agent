package main

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/pkg/errors"
	"github.com/step-security/agent/pkg/artifact"
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
	WorkingDirectory string
	Events           map[int]*Event
	PidIPAddressMap  map[string]bool
	PidFileMap       map[string]bool
	ProcessMap       map[string]*Process
	mutex            sync.RWMutex
	Artifacts        []artifact.Artifact
}

type Process struct {
	PID              string
	Exe              string
	WorkingDirectory string
	Arguments        []string
	Scenario         string // npm publish, dotnet push are scenarios
	Artifacts        []*artifact.Artifact
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
	Timestamp        time.Time
	EventType        string
	Status           string
}

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {

	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		errc <- errors.Wrap(err, "failed to new audit client")
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		errc <- errors.Wrap(err, "failed to get audit client status")
	}

	if status.Enabled == 0 {
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			errc <- errors.Wrap(err, "failed to set audit client")
		}
	}

	if _, err = client.DeleteRules(); err != nil {
		errc <- errors.Wrap(err, "failed to delete audit rules")
	}

	// files modified in working directory
	r, _ := flags.Parse(fmt.Sprintf("-w %s -p wa -k %s", "/home/runner", fileMonitorTag))

	actualBytes, _ := rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	r, _ = flags.Parse(fmt.Sprintf("-w %s -p wa -k %s", "/home/agent", fileMonitorTag))
	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	// syscall connect
	r, _ = flags.Parse(fmt.Sprintf("-a exit,always -S connect -k %s", netMonitorTag))

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule for syscall connect")
	}

	// syscall process start
	r, _ = flags.Parse(fmt.Sprintf("-a exit,always -S execve -k %s", processMonitorTag))

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule for syscall execve")
	}

	/*if status.Enabled != 2 {
		writeToFile("setting kernel settings as immutable")
		if err = client.SetImmutable(libaudit.NoWait); err != nil {
			return err
		}
	}*/

	// sending message to kernel registering our PID
	if err = client.SetPID(libaudit.NoWait); err != nil {
		errc <- errors.Wrap(err, "failed to set audit PID")
	}

	p.receive(client)
}

func (p *ProcessMonitor) receive(r *libaudit.AuditClient) error {

	p.Events = make(map[int]*Event)
	eventHandler := EventHandler{CorrelationId: p.CorrelationId, Repo: p.Repo, ApiClient: p.ApiClient}
	eventHandler.ProcessConnectionMap = make(map[string]bool)
	eventHandler.ProcessFileMap = make(map[string]bool)
	eventHandler.ProcessMap = make(map[string]*Process)

	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		//writeToFile(fmt.Sprintf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data)))
		message, err := auparse.Parse(rawEvent.Type, string(rawEvent.Data))
		if err != nil {
			return errors.Wrap(err, "parse failed.")
		}
		eventMap := message.ToMapStr()

		p.PrepareEvent(int(message.Sequence), eventMap)
		if isEventReady(p.Events[int(message.Sequence)]) {
			go eventHandler.HandleEvent(p.Events[int(message.Sequence)])
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

func (p *ProcessMonitor) PrepareEvent(sequence int, eventMap map[string]interface{}) {
	p.mutex.Lock()
	_, found := p.Events[sequence]
	if !found {
		p.Events[sequence] = &Event{}
	}
	writeLog(fmt.Sprintf("%v", eventMap))
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
	p.Events[sequence].Path = getValue("cwd", eventMap)

	// Connect
	p.Events[sequence].IPAddress = getValue("addr", eventMap)
	p.Events[sequence].Port = getValue("port", eventMap)

	// Process start
	argc, found := eventMap["argc"]

	if found {
		argCountStr := fmt.Sprintf("%v", argc)
		argCount, err := strconv.Atoi(argCountStr)
		if err != nil {
			writeLog(fmt.Sprintf("could not parse argc:%v", argc))
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

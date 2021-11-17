//go:build darwin
// +build darwin

package main

import (
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
	WorkingDirectory string
	Events           map[int]*Event
	PidIPAddressMap  map[string]bool
	PidFileMap       map[string]bool
	ProcessMap       map[string]*Process
	mutex            sync.RWMutex
}

type Process struct {
	PID              string
	Exe              string
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
	Timestamp        time.Time
	EventType        string
	Status           string
}

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {
	writeLog("Monitor Processes called")
}

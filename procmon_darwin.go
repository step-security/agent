//go:build darwin
// +build darwin

package main

import (
	"fmt"
)

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {
	writeLog("Monitor Processes called")
}

func getParentProcessId(pid string) (int, error) {
	return -1, fmt.Errorf("not implemented")
}

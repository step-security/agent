//go:build darwin
// +build darwin

package main

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {
	writeLog("Monitor Processes called")
}

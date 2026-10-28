//go:build linux
// +build linux

package main

import (
	"fmt"
	"runtime"

	"io/ioutil"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/pkg/errors"
)

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {
	WriteLog("\n")
	WriteLog("Monitor Processes called")

	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		errc <- errors.Wrap(err, "failed to new audit client")
	}
	defer client.Close()

	WriteLog("NewAuditClient created")

	status, err := client.GetStatus()
	if err != nil {
		errc <- errors.Wrap(err, "failed to get audit client status")
	}

	if err = configureBackpressure(client, status); err != nil {
		WriteLog(fmt.Sprintf("[procmon] failed to configure audit backlog: %v", err))
	}
	stopLostCheck := make(chan struct{})
	defer close(stopLostCheck)
	go p.monitorKernelLost(status.Lost, stopLostCheck)

	if status.Enabled == 0 {
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			errc <- errors.Wrap(err, "failed to set audit client")
		}
	}

	WriteLog("Status is enabled")

	if _, err = client.DeleteRules(); err != nil {
		errc <- errors.Wrap(err, "failed to delete audit rules")
	}

	WriteLog("Rules deleted")

	if !p.DisableFileMonitoring {

		// files modified in working directory
		workingDirectory := p.WorkingDirectory
		if len(workingDirectory) == 0 {
			workingDirectory = "/home/runner"
		}

		auditRule := fileMonitorAuditRule(workingDirectory, runtime.GOARCH)

		r, _ := flags.Parse(auditRule)

		actualBytes, _ := rule.Build(r)

		if err = client.AddRule(actualBytes); err != nil {
			WriteLog(fmt.Sprintf("failed to add audit rule %v", err))
			errc <- errors.Wrap(err, "failed to add audit rule")
		}

		WriteLog(fmt.Sprintf("File monitor added for %s", workingDirectory))
	}

	r, _ := flags.Parse(fmt.Sprintf("-w %s -p w -k %s", "/home/agent", fileMonitorTag))
	actualBytes, _ := rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	WriteLog("Agent file monitor added")

	r, _ = flags.Parse(fmt.Sprintf("-w %s -p w -k %s", dockerDaemonConfigPath, fileMonitorTag))
	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule for dockerDaemonConfigPath %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	WriteLog("Docker's daemon.json file monitor added")

	r, _ = flags.Parse(fmt.Sprintf("-w %s -p w -k %s", resolvedConfigPath, fileMonitorTag))
	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule for resolvedConfigPath %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	WriteLog("Systemd's resolved.conf file monitor added")

	// syscall connect
	r, _ = flags.Parse(fmt.Sprintf("-a exit,always -S connect -k %s", netMonitorTag))

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule for syscall connect")
	}

	WriteLog("Net monitor added for TCP (connect)")

	// syscall sendto (for UDP)
	r, _ = flags.Parse(fmt.Sprintf("-a exit,always -S sendto -S sendmsg -k %s", netMonitorTag))

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule for sendto %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule for syscall sendto")
	}

	WriteLog("Net monitor added for UDP (sendto & sendmsg)")

	// syscall process start
	r, _ = flags.Parse(fmt.Sprintf("-a exit,always -S execve -k %s", processMonitorTag))

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		WriteLog(fmt.Sprintf("failed to add audit rule %v", err))
		errc <- errors.Wrap(err, "failed to add audit rule for syscall execve")
	}

	/*if status.Enabled != 2 {
		writeToFile("setting kernel settings as immutable")
		if err = client.SetImmutable(libaudit.NoWait); err != nil {
			return err
		}
	}*/
	WriteLog("Process monitor added")

	// sending message to kernel registering our PID
	if err = client.SetPID(libaudit.NoWait); err != nil {
		errc <- errors.Wrap(err, "failed to set audit PID")
	}

	WriteLog("receive called")
	WriteLog("\n")

	if err := p.receive(client); err != nil {
		WriteLog(fmt.Sprintf("[procmon] receive stopped: %v", err))
	}
}

// auditQueueControl is the part of the audit client that sets the kernel queue.
type auditQueueControl interface {
	SetFailure(fm libaudit.FailureMode, wm libaudit.WaitMode) error
	SetBacklogLimit(limit uint32, wm libaudit.WaitMode) error
	SetBacklogWaitTime(waitTime int32, wm libaudit.WaitMode) error
	SetRateLimit(perSecondLimit uint32, wm libaudit.WaitMode) error
}

// configureBackpressure follows Auditbeat's default "auto" strategy: raise the
// backlog limit and have the kernel drop records immediately when the queue is
// full, instead of making the audited syscall wait. Kernels that cannot set the
// wait time get a rate limit instead. The failure mode is set to silent first,
// as Auditbeat does, so a dropped record never panics the kernel.
func configureBackpressure(c auditQueueControl, status *libaudit.AuditStatus) error {
	if status.Enabled == 2 { // locked, changes are rejected
		return nil
	}

	if status.Failure != uint32(libaudit.SilentOnFailure) {
		if err := c.SetFailure(libaudit.SilentOnFailure, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "set failure mode")
		}
	}

	if status.BacklogLimit != auditBacklogLimit {
		if err := c.SetBacklogLimit(auditBacklogLimit, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "set backlog limit")
		}
	}

	var rateLimit uint32
	if status.FeatureBitmap&libaudit.AuditFeatureBitmapBacklogWaitTime != 0 {
		if err := c.SetBacklogWaitTime(0, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "set backlog wait time")
		}
	} else {
		rateLimit = auditFallbackRateLimit
	}

	if status.RateLimit != rateLimit {
		if err := c.SetRateLimit(rateLimit, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "set rate limit")
		}
	}

	WriteLog(fmt.Sprintf("[procmon] audit backlog limit %d, wait time 0: %t, rate limit %d", auditBacklogLimit, rateLimit == 0, rateLimit))
	return nil
}

// monitorKernelLost polls the kernel's lost record counter on its own
// connection, as Auditbeat does, so dropped records show up in the log. It
// stops when done is closed.
func (p *ProcessMonitor) monitorKernelLost(lost uint32, done <-chan struct{}) {
	var client *libaudit.AuditClient
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	ticker := time.NewTicker(kernelLostCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		if client == nil {
			c, err := libaudit.NewAuditClient(nil)
			if err != nil {
				continue
			}
			client = c
		}
		status, err := client.GetStatus()
		if err != nil {
			client.Close()
			client = nil
			continue
		}
		lost = p.noteKernelLost(lost, status.Lost)
	}
}

// noteKernelLost counts records the kernel dropped since the last check and
// returns the new reading. A smaller reading means the counter was reset.
func (p *ProcessMonitor) noteKernelLost(last, current uint32) uint32 {
	delta := current
	if current >= last {
		delta = current - last
	}
	if delta > 0 {
		noteLoss(&p.kernelLost, int64(delta), "kernel reported lost audit records")
	}
	return current
}

func fileMonitorAuditRule(workingDirectory, goarch string) string {
	if goarch == "arm64" {
		return fmt.Sprintf("-a exit,always -F dir=%s -F perm=wa -S openat -S renameat -k %s", workingDirectory, fileMonitorTag)
	}

	return fmt.Sprintf("-a exit,always -F dir=%s -F perm=wa -S open -S openat -S rename -S renameat -k %s", workingDirectory, fileMonitorTag)
}

func (p *ProcessMonitor) receive(r *libaudit.AuditClient) error {

	eventHandler := EventHandler{CorrelationId: p.CorrelationId, Repo: p.Repo, ApiClient: p.ApiClient, DNSProxy: p.DNSProxy}
	eventHandler.ProcessConnectionMap = make(map[string]bool)
	eventHandler.ProcessFileMap = make(map[string]bool)
	eventHandler.SourceCodeMap = make(map[string][]*Event)
	eventHandler.ProcessMap = make(map[string]*Process)
	eventHandler.FileOverwriteCounterMap = make(map[string]int)

	dispatch := p.dispatchEvent
	if dispatch == nil {
		dispatch = func(event *Event) { go eventHandler.HandleEvent(event) }
	}

	reassembler, err := libaudit.NewReassembler(reassemblerMaxInFlight, reassemblerTimeout, &auditStream{monitor: p, dispatch: dispatch})
	if err != nil {
		return errors.Wrap(err, "create reassembler")
	}
	done := make(chan struct{})
	var maintaining sync.WaitGroup
	maintaining.Add(1)
	go func() {
		defer maintaining.Done()
		maintainReassembler(reassembler, done)
	}()
	// stop maintenance before the final flush, so no callback runs after return
	defer func() {
		close(done)
		maintaining.Wait()
		reassembler.Close()
	}()

	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			// EBADF means the client was closed
			if errors.Is(err, syscall.EBADF) {
				return errors.Wrap(err, "receive failed")
			}
			p.noteReceiveError(err)
			if !errors.Is(err, syscall.ENOBUFS) {
				time.Sleep(10 * time.Millisecond) // do not spin on a persistent error
			}
			continue
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		if err := reassembler.Push(rawEvent.Type, rawEvent.Data); err != nil {
			noteLoss(&p.invalidRecords, 1, fmt.Sprintf("dropped audit record with an invalid header: %v", err))
		}
	}
}

// maintainReassembler gives up on events whose last record did not arrive in
// time, as Auditbeat does, until done is closed.
func maintainReassembler(r *libaudit.Reassembler, done <-chan struct{}) {
	ticker := time.NewTicker(reassemblerMaintain)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := r.Maintain(); err != nil {
				return
			}
		}
	}
}

func getParentProcessId(pid string) (int, error) {
	statPath := fmt.Sprintf("/proc/%s/stat", pid)
	dataBytes, err := ioutil.ReadFile(statPath)
	if err != nil {
		return -1, err
	}

	data := string(dataBytes)
	binStart := strings.IndexRune(data, '(') + 1
	binEnd := strings.IndexRune(data[binStart:], ')')

	var ppid, pgrp, sid int
	var state rune

	// Move past the image name and start parsing the rest
	data = data[binStart+binEnd+2:]
	_, err = fmt.Sscanf(data,
		"%c %d %d %d",
		&state,
		&ppid,
		&pgrp,
		&sid)

	return ppid, err
}

func getProcessExe(pid string) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}

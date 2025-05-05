package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	agentLockFile = "agent.lock"
)

func getPidsOfInterest() []uint32 {
	out := []uint32{}

	// our process
	out = append(out, uint32(os.Getpid()))

	return out
}

func getFilesOfInterest() []string {
	out := []string{}

	// sudoers file
	out = append(out, "/etc/sudoers.d/runner")

	// resolved.conf
	out = append(out, "/etc/resolv.conf")

	// /etc/systemd/resolved.conf
	out = append(out, "/etc/systemd/resolved.conf")

	// /etc/docker/daemon.json
	out = append(out, "/etc/docker/daemon.json")

	return out
}

func getProcFilesOfInterest() []string {
	out := []string{}

	// runner worker memory files
	runnerWorker, _ := pidOf("Runner.Worker")
	out = append(out, getProcMemFiles(runnerWorker)...)

	// runner listener memory files
	runnerListener, _ := pidOf("Runner.Listener")
	out = append(out, getProcMemFiles(runnerListener)...)

	return out
}

func pidOf(procName string) (uint64, error) {

	cmd := exec.Command("pidof", procName)

	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	if len(out) == 0 {
		return 0, fmt.Errorf("no process exists")
	}

	parts := strings.Fields(string(out))

	num, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	return uint64(num), nil

}

func getProcMemFiles(pid uint64) []string {

	out := []string{}

	if pid == 0 {
		return out
	}

	out = []string{
		fmt.Sprintf("/proc/%d/mem", pid),
	}

	return out
}

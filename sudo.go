package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

type Sudo struct {
	SudoersBackUpPath string
}

// sudoersFile is a var so tests can point it at a temp file
var sudoersFile = "/etc/sudoers.d/runner"

const runnerUser = "runner"

// runCmd is a var so tests can inject a fake command runner
var runCmd = run

// socket paths are vars so tests can point them at temp files
var dockerSockPath = "/var/run/docker.sock"
var containerdSockPath = "/run/containerd/containerd.sock"

func (s *Sudo) disableSudo(tempDir string) error {
	s.SudoersBackUpPath = path.Join(tempDir, "runner")
	err := copy(sudoersFile, s.SudoersBackUpPath)

	if err != nil {
		return fmt.Errorf("error backing up sudoers file: %v", err)
	}
	err = os.Truncate(sudoersFile, 0)
	if err != nil {
		return fmt.Errorf("unable to delete sudoers file at %s: %v", sudoersFile, err)
	}

	return nil
}

func (s *Sudo) revertDisableSudo() error {
	if len(s.SudoersBackUpPath) > 0 {
		err := copy(s.SudoersBackUpPath, sudoersFile)

		if err != nil {
			return fmt.Errorf("error reverting sudoers file: %v", err)
		}
	}

	return nil
}

func (s *Sudo) disableSudoAndContainers(tempDir string) error {

	var errstrings []string

	// Revoke sudo first: a single truncate syscall. This must happen before
	// any container teardown — the teardown takes several seconds and job
	// steps can start (and run `sudo`) while it is still in progress.
	err := s.disableSudo(tempDir)
	if err != nil {
		WriteLog(fmt.Sprintf("error disabling sudo: %v", err))
		errstrings = append(errstrings, err.Error())
	}

	// Revoke container access second: chmod on the sockets, also instant.
	s.removeSocketPermissions()

	// Slow cleanup runs in the background — it is not enforcement and must
	// not delay it. Purge first (stops the daemon, unmounts overlays), then
	// delete the directories; racing the two makes the delete far slower.
	go func() {
		s.uninstallDocker()
		s.removeDockerDirectoriesAndFiles()
	}()

	//flatten errs
	if len(errstrings) > 0 {
		return fmt.Errorf("error disabling sudo and containers: %s", strings.Join(errstrings, "\n"))
	}
	return nil
}

// removeSocketPermissions removes permissions from Docker and containerd sockets if they exist
func (s *Sudo) removeSocketPermissions() {
	// Check and remove docker.sock permissions if it exists
	if _, err := os.Stat(dockerSockPath); err == nil {
		if err := os.Chmod(dockerSockPath, 0000); err != nil {
			WriteLog(fmt.Sprintf("error removing docker.sock permissions: %v", err))
		}
	}

	// Check and remove containerd.sock permissions if it exists
	if _, err := os.Stat(containerdSockPath); err == nil {
		if err := os.Chmod(containerdSockPath, 0000); err != nil {
			WriteLog(fmt.Sprintf("error removing containerd.sock permissions: %v", err))
		}
	}
}

func run(cmd string, args ...string) {
	WriteLog(fmt.Sprintf("Running: %s %v", cmd, args))
	c := exec.Command(cmd, args...)

	stdout, _ := c.StdoutPipe()
	stderr, _ := c.StderrPipe()

	if err := c.Start(); err != nil {
		WriteLog(fmt.Sprintf("Failed to start command: %s", err))
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			WriteLog(scanner.Text())
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			WriteLog(scanner.Text())
		}
	}()

	if err := c.Wait(); err != nil {
		WriteLog(fmt.Sprintf("Command failed: %v", err))
	}
}

func (s *Sudo) uninstallDocker() error {
	WriteLog("Uninstalling docker")
	runCmd("apt-get", "purge", "-y",
		"docker-ce", "docker-ce-cli", "containerd.io")
	return nil
}

func (s *Sudo) removeDockerDirectoriesAndFiles() error {
	runCmd("rm", "-rf", "/var/lib/docker")
	runCmd("rm", "-rf", "/var/lib/containerd")
	runCmd("rm", "-f", "/etc/apt/sources.list.d/docker.list")
	runCmd("rm", "-f", "/etc/apt/keyrings/docker.asc")
	return nil
}

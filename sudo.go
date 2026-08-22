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

	// test seams; zero values fall back to the real paths and command runner.
	// These are per-instance fields rather than package vars so the background
	// container-cleanup goroutine never reads state a test restores later.
	sudoersFilePathOverride string
	dockerSockPathOverride  string
	containerdSockOverride  string
	runCmd                  func(cmd string, args ...string)
}

const runnerUser = "runner"

func (s *Sudo) sudoersFilePath() string {
	if s.sudoersFilePathOverride != "" {
		return s.sudoersFilePathOverride
	}
	return "/etc/sudoers.d/runner"
}

func (s *Sudo) dockerSockPath() string {
	if s.dockerSockPathOverride != "" {
		return s.dockerSockPathOverride
	}
	return "/var/run/docker.sock"
}

func (s *Sudo) containerdSockPath() string {
	if s.containerdSockOverride != "" {
		return s.containerdSockOverride
	}
	return "/run/containerd/containerd.sock"
}

func (s *Sudo) exec(cmd string, args ...string) {
	if s.runCmd != nil {
		s.runCmd(cmd, args...)
		return
	}
	run(cmd, args...)
}

func (s *Sudo) disableSudo(tempDir string) error {
	sudoersFile := s.sudoersFilePath()
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
		err := copy(s.SudoersBackUpPath, s.sudoersFilePath())

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
	if _, err := os.Stat(s.dockerSockPath()); err == nil {
		if err := os.Chmod(s.dockerSockPath(), 0000); err != nil {
			WriteLog(fmt.Sprintf("error removing docker.sock permissions: %v", err))
		}
	}

	// Check and remove containerd.sock permissions if it exists
	if _, err := os.Stat(s.containerdSockPath()); err == nil {
		if err := os.Chmod(s.containerdSockPath(), 0000); err != nil {
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
	s.exec("apt-get", "purge", "-y",
		"docker-ce", "docker-ce-cli", "containerd.io")
	return nil
}

func (s *Sudo) removeDockerDirectoriesAndFiles() error {
	s.exec("rm", "-rf", "/var/lib/docker")
	s.exec("rm", "-rf", "/var/lib/containerd")
	s.exec("rm", "-f", "/etc/apt/sources.list.d/docker.list")
	s.exec("rm", "-f", "/etc/apt/keyrings/docker.asc")
	return nil
}

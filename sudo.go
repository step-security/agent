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

const (
	sudoersFile = "/etc/sudoers.d/runner"
	runnerUser  = "runner"
)

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

	s.removeDockerDirectoriesAndFiles()

	// Remove socket permissions if they exist
	s.removeSocketPermissions()
	var errstrings []string

	err := s.disableSudo(tempDir)
	if err != nil {
		WriteLog(fmt.Sprintf("error disabling sudo: %v", err))
		errstrings = append(errstrings, err.Error())
	}

	//flatten errs
	if len(errstrings) > 0 {
		return fmt.Errorf("error disabling sudo and containers: %s", strings.Join(errstrings, "\n"))
	}
	return nil
}

// removeSocketPermissions removes permissions from Docker and containerd sockets if they exist
func (s *Sudo) removeSocketPermissions() {
	// Check and remove docker.sock permissions if it exists
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "000", "/var/run/docker.sock")
		err := cmd.Run()
		if err != nil {
			WriteLog(fmt.Sprintf("error removing docker.sock permissions: %v", err))
		}
	}

	// Check and remove containerd.sock permissions if it exists
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "000", "/run/containerd/containerd.sock")
		err := cmd.Run()
		if err != nil {
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
	run("sudo", "apt-get", "purge", "-y",
		"docker-ce", "docker-ce-cli", "containerd.io")
	return nil
}

func (s *Sudo) removeDockerDirectoriesAndFiles() error {
	run("sudo", "rm", "-rf", "/var/lib/docker")
	run("sudo", "rm", "-rf", "/var/lib/containerd")
	run("sudo", "rm", "-f", "/etc/apt/sources.list.d/docker.list")
	run("sudo", "rm", "-f", "/etc/apt/keyrings/docker.asc")
	return nil
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
)

type Sudo struct {
	SudoersBackUpPath string
}

const (
	sudoersFile = "/etc/sudoers.d/runner"
)

func (s *Sudo) disableSudo(tempDir string) error {
	s.SudoersBackUpPath = path.Join(tempDir, "runner")
	err := copy(sudoersFile, s.SudoersBackUpPath)

	if err != nil {
		return fmt.Errorf("error backing up sudoers file: %v", err)
	}
	err = os.Remove(sudoersFile)
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

	// Remove socket permissions if they exist
	s.removeSocketPermissions()

	// Remove user from docker group
	if err := s.removeUserFromDockerGroup(); err != nil {
		return err
	}

	err := s.disableSudo(tempDir)
	if err != nil {
		return err
	}

	return nil
}

// removeSocketPermissions removes permissions from Docker and containerd sockets if they exist
func (s *Sudo) removeSocketPermissions() {
	// Check and remove docker.sock permissions if it exists
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "000", "/var/run/docker.sock")
		cmd.Run()
	}

	// Check and remove containerd.sock permissions if it exists
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "000", "/run/containerd/containerd.sock")
		cmd.Run()
	}
}

// removeUserFromDockerGroup removes the current user from the docker group
func (s *Sudo) removeUserFromDockerGroup() error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error getting current user: %v", err)
	}

	cmd := exec.Command("sudo", "gpasswd", "-d", currentUser.Username, "docker")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// It's okay if the user is not in the docker group
		if len(output) > 0 {
			// Check if the error is because the user is not a member
			if fmt.Sprintf("%s", output) != fmt.Sprintf("gpasswd: user '%s' is not a member of 'docker'\n", currentUser.Username) {
				return fmt.Errorf("error removing user from docker group: %v, output: %s", err, output)
			}
		}
	}
	return nil
}

// revertDisableSudoAndContainers reverts the changes made by disableSudoAndContainers
func (s *Sudo) revertDisableSudoAndContainers() error {
	// Step 1: Restore the sudoers file from backup
	s.revertDisableSudo()

	// Step 2: Restore socket permissions
	s.restoreSocketPermissions()

	// Step 3: Add user back to docker group
	if err := s.addUserToDockerGroup(); err != nil {
		return fmt.Errorf("error adding user back to docker group: %v", err)
	}

	return nil
}

// restoreSocketPermissions restores permissions to Docker and containerd sockets
func (s *Sudo) restoreSocketPermissions() {
	// Check if docker socket exists before restoring
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "660", "/var/run/docker.sock")
		cmd.Run()
	}

	// Check if containerd socket exists before restoring
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		cmd := exec.Command("sudo", "chmod", "660", "/run/containerd/containerd.sock")
		cmd.Run()
	}
}

// addUserToDockerGroup adds the current user back to the docker group
func (s *Sudo) addUserToDockerGroup() error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error getting current user: %v", err)
	}

	cmd := exec.Command("sudo", "gpasswd", "-a", currentUser.Username, "docker")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding user back to docker group: %v, output: %s", err, output)
	}
	return nil
}

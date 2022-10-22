package main

import (
	"fmt"
	"os"
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
		return fmt.Errorf(fmt.Sprintf("error backing up sudoers file: %v", err))
	}
	err = os.Remove(sudoersFile)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("unable to delete sudoers file at %s: %v", sudoersFile, err))
	}

	return nil
}

func (s *Sudo) revertDisableSudo() error {
	if len(s.SudoersBackUpPath) > 0 {
		err := copy(s.SudoersBackUpPath, sudoersFile)

		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error reverting sudoers file: %v", err))
		}
	}

	return nil
}

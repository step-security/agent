package artifact

import (
	"path"
	"time"

	"github.com/go-git/go-git/v5"
)

type Artifact struct {
	Name         string      `json:"name"`
	FilePath     string      `json:"filepath"`
	SHA256       string      `json:"sha256"`
	TimeStamp    time.Time   `json:"timestamp"`
	Version      string      `json:"version,omitempty"`
	Location     string      `json:"location,omitempty"` // where was it downloaded from
	Remote       string      `json:"remote,omitempty"`   // source location of the generated artifact
	GitPath      string      `json:"gitpath,omitempty"`  // source location of the generated artifact
	Type         string      `json:"type,omitempty"`     // npm/ go/ container
	Dependencies []*Artifact `json:"dependencies,omitempty"`
	Tool         Tool        `json:"tool"`
}

type Tool struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

func (a *Artifact) AddMetadata(workingDirectory, packageJsonFolder string) {
	localGit, err := git.PlainOpen(a.GitPath)
	if err != nil {
		return
	}
	remotes, err := localGit.Remotes()
	if err == nil && len(remotes) > 0 {
		a.Remote = remotes[0].String()
	}

	// get name and version from package.json
	packageMetadata, _ := GetPackageMetadata(path.Join(packageJsonFolder, "package.json"))
	a.Name = packageMetadata.Name
	a.Version = packageMetadata.Version
	a.Type = "npm"

	// add dependencies
	dependencies, _ := GetDependenciesFromPackageLock(path.Join(workingDirectory, "package-lock.json"))
	a.Dependencies = dependencies

	if dependencies == nil {
		dependencies, _ := GetDependenciesFromPackageLock(path.Join(workingDirectory, "node_modules", ".package-lock.json"))
		a.Dependencies = dependencies
	}
}

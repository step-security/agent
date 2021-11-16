package artifact

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
)

type PackageLock struct {
	LockfileVersion int                `json:"lockfileVersion"`
	Requires        bool               `json:"requires"`
	Packages        map[string]Package `json:"packages"`
}

type PackageMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Package struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	InBundle  bool   `json:"inBundle"`
	License   string `json:"license"`
}

func GetDependenciesFromPackageLock(packageLockPath string) ([]*Artifact, error) {
	var packageLock PackageLock
	data, err := ioutil.ReadFile(packageLockPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read package lock file")
	}

	err = json.Unmarshal([]byte(data), &packageLock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal package lock file")
	}

	if packageLock.LockfileVersion != 2 && packageLock.LockfileVersion != 3 {
		return nil, fmt.Errorf("lockfile version must be 2 or 3")
	}

	var dependencies []*Artifact
	for key, p := range packageLock.Packages {
		if !p.Dev {
			splitKey := strings.Split(key, "/")
			name := splitKey[len(splitKey)-1]
			dependencies = append(dependencies, &Artifact{Name: name, Location: p.Resolved, SHA256: p.Integrity, Version: p.Version, Type: "npm"})
		}
	}
	return dependencies, nil
}

func GetPackageMetadata(packageJsonPath string) (*PackageMetadata, error) {
	var packageMetadata PackageMetadata
	data, err := ioutil.ReadFile(packageJsonPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read package file")
	}

	err = json.Unmarshal([]byte(data), &packageMetadata)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal package file")
	}

	return &packageMetadata, nil
}

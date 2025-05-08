package main

import "fmt"

// filled through ldflags
var (
	ReleaseTag    = ""
	ReleaseBranch = ""
	ReleaseCommit = ""
)

func LogBuildInfo() {
	WriteLog(fmt.Sprintf("[buildInfo] tag=%s commit=%s branch=%s \n", ReleaseTag, ReleaseCommit, ReleaseBranch))
}

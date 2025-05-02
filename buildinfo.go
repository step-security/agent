package main

import "fmt"

// filled through ldflags
var (
	ReleaseTag = ""
	commit     = ""
)

func LogBuildInfo() {
	WriteLog(fmt.Sprintf("[buildInfo] tag=%s commit=%s \n", ReleaseTag, commit))
}

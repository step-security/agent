package main

import (
	"encoding/json"
	"flag"
	"time"
)

var (
	artifactPath  = flag.String("artifact_path", "", "The file or dir path of the artifacts for which provenance should be generated.")
	outputPath    = flag.String("output_path", "build.provenance", "The path to which the generated provenance should be written.")
	githubContext = flag.String("github_context", "", "The '${github}' context value.")
	runnerContext = flag.String("runner_context", "", "The '${runner}' context value.")
)

const (
	GitHubHostedIdSuffix = "/Attestations/GitHubHostedActions@v1"
	SelfHostedIdSuffix   = "/Attestations/SelfHostedActions@v1"
	TypeId               = "https://github.com/Attestations/arjundashrath/harden-runner@v1"
	PayloadContentType   = "application/vnd.in-toto+json"
)

type GitHubContext struct {
	Action          string          `json:"action"`
	ActionPath      string          `json:"action_path"`
	Actor           string          `json:"actor"`
	BaseRef         string          `json:"base_ref"`
	Event           json.RawMessage `json:"event"`
	EventName       string          `json:"event_name"`
	EventPath       string          `json:"event_path"`
	HeadRef         string          `json:"head_ref"`
	Job             string          `json:"job"`
	Ref             string          `json:"ref"`
	Repository      string          `json:"repository"`
	RepositoryOwner string          `json:"repository_owner"`
	RunId           string          `json:"run_id"`
	RunNumber       string          `json:"run_number"`
	SHA             string          `json:"sha"`
	Token           string          `json:"token,omitempty"`
	Workflow        string          `json:"workflow"`
	Workspace       string          `json:"workspace"`
}
type RunnerContext struct {
	OS        string `json:"os"`
	Temp      string `json:"temp"`
	ToolCache string `json:"tool_cache"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     `json:"predicate"`
}

type Subject struct {
	Name   string    `json:"name"`
	Digest DigestSet `json:"digest"`
}

//func generateSubject() Subject {
//TO DO
//}

type DigestSet map[string]string
type Item struct {
	URI    string    `json:"uri"`
	Digest DigestSet `json:"digest"`
}

type AnyContext struct {
	GitHubContext `json:"github"`
	RunnerContext `json:"runner"`
}

type Predicate struct {
	Builder   `json:"builder"`
	Metadata  `json:"metadata"`
	Recipe    `json:"recipe"`
	Materials []Item `json:"materials"`
}
type Builder struct {
	Id string `json:"id"`
}
type Metadata struct {
	BuildInvocationId string `json:"buildInvocationId"`
	Completeness      `json:"completeness"`
	Reproducible      bool `json:"reproducible"`
	// BuildStartedOn not defined as it's not available from a GitHub Action.
	BuildFinishedOn string `json:"buildFinishedOn"`
}
type Recipe struct {
	Type              string          `json:"type"`
	DefinedInMaterial int             `json:"definedInMaterial"`
	EntryPoint        string          `json:"entryPoint"`
	Arguments         json.RawMessage `json:"arguments"`
	Environment       *AnyContext     `json:"environment"`
}
type Completeness struct {
	Arguments   bool `json:"arguments"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}

func provgen() Statement {

	stm := Statement{PredicateType: "https://slsa.dev/provenance/v0.1", Type: "https://in-toto.io/Statement/v0.1"}
	//stm.Subject = append(stmt.Subject, generateSubject...)
	stm.Predicate = Predicate{
		Builder{},
		Metadata{
			Completeness: Completeness{
				Arguments:   true,
				Environment: false,
				Materials:   false,
			},
			Reproducible:    false,
			BuildFinishedOn: time.Now().UTC().Format(time.RFC3339),
		},
		Recipe{
			Type:              TypeId,
			DefinedInMaterial: 0,
		},
		[]Item{},
	}

	context := AnyContext{}

	gh := context.GitHubContext

	// NOTE: Re-runs are not uniquely identified and can cause run ID collisions.
	repourl := "https://github.com/" + gh.Repository

	stm.Predicate.Builder.Id = repourl

	stm.Predicate.Metadata.BuildInvocationId = repourl + "/actions/runs/" + gh.RunId

	return stm
}

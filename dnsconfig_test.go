package main

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"testing"
)

func createTempFileWithContents(content string) string {
	file, err := ioutil.TempFile("", "*.json")
	if err != nil {
		log.Fatal(err)
	}

	_, err = file.WriteString(content)
	if err != nil {
		log.Fatal(err)
	}

	return file.Name()
}

func Test_updateDockerConfig(t *testing.T) {
	type args struct {
		configPath string
	}
	tmpFileName := createTempFileWithContents("{ \"cgroup-parent\": \"/actions_job\"}")
	mockDockerConfigPath, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	mockDockerConfigPath = path.Join(mockDockerConfigPath, "test.json")
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "existing file",
			args:    args{configPath: tmpFileName},
			want:    "{\"cgroup-parent\":\"/actions_job\",\"dns\":[\"172.17.0.1\"]}",
			wantErr: false},
		{name: "non existent file",
			args:    args{configPath: mockDockerConfigPath},
			want:    "{\"dns\":[\"172.17.0.1\"]}",
			wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := updateDockerConfig(tt.args.configPath); (err != nil) != tt.wantErr {
				t.Errorf("updateDockerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			content, err := ioutil.ReadFile(tt.args.configPath)
			if err != nil {
				log.Fatal(err)
			}
			if strings.Compare(string(content), tt.want) != 0 {
				t.Errorf("updateDockerConfig() = %s, want %s", string(content), tt.want)
			}
			defer os.Remove(tt.args.configPath)
		})
	}
}

func Test_writeResolveConfig(t *testing.T) {
	type args struct {
		configPath string
	}
	tmpFileName := createTempFileWithContents("Existing DNS settings")
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "overwrite file",
			args:    args{configPath: tmpFileName},
			want:    "[Resolve]\nDNS=127.0.0.1\n",
			wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeResolveConfig(tt.args.configPath); (err != nil) != tt.wantErr {
				t.Errorf("writeResolveConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			content, err := ioutil.ReadFile(tt.args.configPath)
			if err != nil {
				log.Fatal(err)
			}
			if strings.Compare(string(content), tt.want) != 0 {
				t.Errorf("writeResolveConfig() = %s, want %s", string(content), tt.want)
			}
			defer os.Remove(tt.args.configPath)
		})
	}
}

package piperutils

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/SAP/jenkins-library/pkg/command"
	"github.com/SAP/jenkins-library/pkg/log"
)

const (
	NAME_REGEX     = "(?s)(.*)name=['\"](.*?)['\"](.*)"
	VERSION_REGEX  = "(?s)(.*)version=['\"](.*?)['\"](.*)"
	METHOD_REGEX   = "(?s)(.*)\\(\\)"
	EVALUATE_REGEX = "/.*?\\$\\{.*?\\}.*/"
)

type POMDescriptor struct {
	XMLName    xml.Name `xml:"project"`
	Packaging  string   `xml:"packaging"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
}

func GetMavenGAV(file string, cmd command.Command) (*POMDescriptor, error) {

	descriptor := new(POMDescriptor)

	content, err := readPom(file)
	if err != nil {
		return descriptor, err
	}

	err = xml.Unmarshal([]byte(content), descriptor)
	if err != nil {
		return descriptor, err
	}

	buf := new(bytes.Buffer)

	cmd.Stdout(buf)
	cmd.Stderr(log.Entry().Writer())

	if evaluateResult(descriptor.GroupID) {
		cmd.RunExecutable(fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.groupId | grep -Ev '(^\\s*\\[|Download|Java\\w+:)'", file))
		descriptor.GroupID = strings.Trim(buf.String(), " ")
	}
	if evaluateResult(descriptor.ArtifactID) {
		cmd.RunExecutable(fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.artifactId | grep -Ev '(^\\s*\\[|Download|Java\\w+:)'", file))
		descriptor.ArtifactID = strings.Trim(buf.String(), " ")
	}
	if evaluateResult(descriptor.Version) {
		cmd.RunExecutable(fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.version | grep ^[0-9].*", file))
		descriptor.Version = strings.Trim(buf.String(), " ")
	}

	return descriptor, nil
}

func evaluateResult(value string) bool {
	if len(value) > 0 {
		match, err := regexp.MatchString(EVALUATE_REGEX, value)
		if err != nil || match {
			return true
		}
		return false
	}
	return true
}

func readPom(file string) (string, error) {

	if len(file) <= 0 {
		file = "pom.xml"
	}

	pom, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer pom.Close()
	content, err := ioutil.ReadAll(pom)
	if err != nil {
		return string(content), err
	}

	return string(content), nil
}

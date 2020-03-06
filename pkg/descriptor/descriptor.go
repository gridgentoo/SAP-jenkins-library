package descriptor

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

func (d POMDescriptor) GetVersion() string { return d.Version }

type PyDescriptor struct {
	Name    string
	Version string
}

func (d PyDescriptor) GetVersion() string { return d.Version }

type Descriptor interface {
	GetVersion() string
}

func GetMavenGAV(file string, cmd command.Command) (*POMDescriptor, error) {

	descriptor := new(POMDescriptor)

	content, err := readFile(file, "pom.xml")
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

	if evaluateResult(descriptor.GroupID, EVALUATE_REGEX) {
		cmd.RunShell("/bin/bash", fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.groupId | grep -Ev '(^\\s*\\[|Download|Java\\w+:)'", file))
		descriptor.GroupID = strings.Trim(buf.String(), " ")
	}
	if evaluateResult(descriptor.ArtifactID, EVALUATE_REGEX) {
		cmd.RunShell("/bin/bash", fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.artifactId | grep -Ev '(^\\s*\\[|Download|Java\\w+:)'", file))
		descriptor.ArtifactID = strings.Trim(buf.String(), " ")
	}
	if evaluateResult(descriptor.Version, EVALUATE_REGEX) {
		cmd.RunShell("/bin/bash", fmt.Sprintf("mvn -f %v help:evaluate -Dexpression=project.version | grep ^[0-9].*", file))
		descriptor.Version = strings.TrimSpace(buf.String())
	}

	return descriptor, nil
}

func getPipGAV(file string) (*PyDescriptor, error) {
	descriptor := new(PyDescriptor)

	content, err := readFile(file, "setup.py")
	if err != nil {
		return descriptor, err
	}

	if evaluateResult(content, NAME_REGEX) {
		compile := regexp.MustCompile(NAME_REGEX)
		values := compile.FindStringSubmatch(content)
		descriptor.Name = values[2]
	} else {
		descriptor.Name = ""
	}
	if evaluateResult(content, VERSION_REGEX) {
		compile := regexp.MustCompile(VERSION_REGEX)
		values := compile.FindStringSubmatch(content)
		descriptor.Version = values[2]
	} else {
		descriptor.Version = ""
	}

	if len(descriptor.Version) <= 0 || evaluateResult(descriptor.Version, METHOD_REGEX) {
		file = strings.Replace(file, "setup.py", "version.txt", 1)
		descriptor.Version, err = getVersionFromFile(file)
		if err != nil {
			return descriptor, err
		}
	}

	return descriptor, nil
}

func evaluateResult(value, regex string) bool {
	if len(value) > 0 {
		match, err := regexp.MatchString(regex, value)
		if err != nil || match {
			return true
		}
		return false
	}
	return true
}

func readFile(file, defaultFile string) (string, error) {

	if len(file) <= 0 {
		file = defaultFile
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

func getVersionFromFile(file string) (string, error) {
	versionString, err := readFile(file, "")
	if err != nil {
		return "", err
	}
	if len(versionString) >= 0 {
		return strings.TrimSpace(versionString), nil
	}
	return "", nil
}

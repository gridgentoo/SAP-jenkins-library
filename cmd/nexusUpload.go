package cmd

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"fmt"
	"github.com/SAP/jenkins-library/pkg/command"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/maven"
	"github.com/SAP/jenkins-library/pkg/nexus"
	"github.com/SAP/jenkins-library/pkg/piperenv"
	"github.com/SAP/jenkins-library/pkg/piperutils"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/ghodss/yaml"
)

func nexusUpload(config nexusUploadOptions, telemetryData *telemetry.CustomData) {
	// for command execution use Command
	c := command.Command{}
	// reroute command output to logging framework
	c.Stdout(log.Entry().Writer())
	c.Stderr(log.Entry().Writer())

	// for http calls import  piperhttp "github.com/SAP/jenkins-library/pkg/http"
	// and use a  &piperhttp.Client{} in a custom system
	// Example: step checkmarxExecuteScan.go

	// error situations should stop execution through log.Entry().Fatal() call which leads to an os.Exit(1) in the end
	err := runNexusUpload(&config, telemetryData, &c)
	if err != nil {
		log.Entry().WithError(err).Fatal("step execution failed")
	}
}

type MtaYaml struct {
	ID      string `json:"ID"`
	Version string `json:"version"`
}

func runNexusUpload(config *nexusUploadOptions, telemetryData *telemetry.CustomData, command execRunner) error {
	projectStructure := piperutils.ProjectStructure{}

	nexusClient := nexus.Upload{Username: config.User, Password: config.Password}
	groupID := config.GroupID // TODO... Only expected to be provided for MTA projects, can be empty, though
	err := nexusClient.SetBaseURL(config.Url, config.Version, config.Repository, groupID)
	if err != nil {
		log.Entry().WithError(err).Fatal()
	}

	if projectStructure.UsesMta() {
		var mtaYaml MtaYaml
		mtaYamContent, _ := ioutil.ReadFile("mta.yaml")
		if err == nil {
			err = yaml.Unmarshal(mtaYamContent, &mtaYaml)
		}
		if err == nil {
			err = nexusClient.SetArtifactsVersion(mtaYaml.Version)
		}
		if err == nil {
			err = nexusClient.AddArtifact(nexus.ArtifactDescription{File: "mta.yaml", Type: "yaml", Classifier: "", ID: config.ArtifactID})
		}
		if err == nil {
			//fixme do proper way to find name/path of mta file
			mtarFilePath := piperenv.GetParameter(".pipeline/commonPipelineEnvironment", "mtarFilePath")
			fmt.Println(mtarFilePath)
			err = nexusClient.AddArtifact(nexus.ArtifactDescription{File: mtarFilePath, Type: "mtar", Classifier: "", ID: config.ArtifactID})
		}
		if err != nil {
			log.Entry().WithError(err).Fatal()
		}
	}

	if projectStructure.UsesMaven() {
		if err == nil {
			err = deployMavenArtifacts(&nexusClient, config, "", "target", "")
		}
		if err == nil {
			err = deployMavenArtifacts(&nexusClient, config, "application", "application/target", config.AdditionalClassifiers)
		}
		if err != nil {
			log.Entry().WithError(err).Fatal()
		}
	}

	nexusClient.UploadArtifacts()

	//log.Entry().WithField("LogField", "Log field content").Info("This is just a demo for a simple step.")
	return nil
}

func deployMavenArtifacts(nexusClient *nexus.Upload, config *nexusUploadOptions, pomPath, targetFolder, additionalClassifiers string) error {
	var err error
	var artifactID string
	var artifactsVersion string
	var packaging string

	pomFile := "pom.xml"
	if pomPath != "" {
		pomFile = pomPath+"/"+pomFile
	}

	artifactID, err = evaluateMavenProperty(pomFile, "project.artifactId")
	if err == nil {
		err = nexusClient.SetArtifactsVersion(artifactID)
	}

	artifactsVersion, err = evaluateMavenProperty(pomFile, "project.version")
	if err == nil {
		err = nexusClient.SetArtifactsVersion(artifactsVersion)
	}

	if err == nil {
		err = nexusClient.AddArtifact(nexus.ArtifactDescription{File: pomFile, Type: "pom", Classifier: "", ID: artifactID})
	}

	packaging, err = evaluateMavenProperty(pomFile, "project.packaging")
	if err == nil {
		if packaging != "pom" {
			if packaging == "" {
				packaging = "jar"
			}
			var finalName string
			finalName, err = evaluateMavenProperty(pomFile, "project.build.finalName")
			if err != nil {
				return err
			}
			fileName := finalName + "." + packaging
			if targetFolder != "" {
				fileName = targetFolder + "/" + fileName
			}
			err = nexusClient.AddArtifact(nexus.ArtifactDescription{File: fileName, Type: packaging, Classifier: "", ID: artifactID})
		}
	}

	if additionalClassifiers != "" {
		var classifiers []classifierDescription
		classifiers, err = getClassifiers(additionalClassifiers)
		if err != nil {
			return err
		}
		for _, classifier := range classifiers {
			fileName := artifactID + "-" + classifier.Classifier + "." + classifier.FileType
			if targetFolder != "" {
				fileName = targetFolder + "/" + fileName
			}
			err = nexusClient.AddArtifact(nexus.ArtifactDescription{File: fileName, Type: classifier.FileType, Classifier: classifier.Classifier, ID: artifactID})
			if err != nil {
				return err
			}
		}
	}

	return err
}

func evaluateMavenProperty(pomFile, expression string) (string, error) {
	execRunner := command.Command{}
	execRunner.Stdout(ioutil.Discard)
	execRunner.Stderr(ioutil.Discard)

	expressionDefine := "-Dexpression="+expression

	options := maven.ExecuteOptions{
		PomPath:      pomFile,
		Goals:        []string{"org.apache.maven.plugins:maven-help-plugin:3.1.0:evaluate"},
		Defines:      []string{expressionDefine, "-DforceStdout", "-q"},
		ReturnStdout: true,
	}
	value, err := maven.Execute(&options, &execRunner)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(value, "null object or invalid expression") {
		return "", errors.New(fmt.Sprintf("Expression could not be resolved, property not found or invalid expression '%s'", expression))
	}
	return value, nil
}

type classifierDescription struct {
	Classifier string `json:"classifier"`
	FileType   string `json:"type"`
}

func getClassifiers(classifiersAsJSON string) ([]classifierDescription, error) {
	var classifiers []classifierDescription
	err := json.Unmarshal([]byte(classifiersAsJSON), &classifiers)
	return classifiers, err
}


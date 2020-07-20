// +build integration
// can be execute with go test -tags=integration ./integration/...

package main

import (
	"fmt"
	"github.com/SAP/jenkins-library/pkg/log"
	"os"
	"testing"
)

func TestCfDeployMavenProject(t *testing.T) {
	t.Parallel()
	username, password := getCredentialsFromEnvironment(t)

	container := givenThisContainer(t, IntegrationTestDockerExecRunnerBundle{
		// The source code for this image is at https://github.com/piper-validation/cloud-s4-sdk-book/tree/consumer-test
		// We use this pre-built image that contains the deployable artifact to avoid
		// a) putting the large file (> 10 mb) into this repo
		// b) avoid the need to build the artifact from source as part of this test
		Image: "ppiper/cloud-foundry-integration-test:maven",
	})

	err := container.whenRunningPiperCommand("cloudFoundryDeploy",
		fmt.Sprintf("--username=%s", username), fmt.Sprintf("--password=%s", password))
	if err != nil {
		t.Fatalf("Piper command failed %s", err)
	}

	container.assertHasOutput(t, "name:              devops-docker-images-IT")
	container.assertHasOutput(t, "Logged out successfully")
}

func TestCfDeployMtaProject(t *testing.T) {
	t.Parallel()
	username, password := getCredentialsFromEnvironment(t)

	container := givenThisContainer(t, IntegrationTestDockerExecRunnerBundle{
		// The source code for this image is at https://github.com/piper-validation/cloud-s4-sdk-book/tree/mta-cf-integration-test
		// We use this pre-built image that contains the deployable artifact to avoid
		// a) putting the large file (> 10 mb) into this repo
		// b) avoid the need to build the artifact from source as part of this test
		Image: "ppiper/cloud-foundry-integration-test:mta",
	})

	err := container.whenRunningPiperCommand("cloudFoundryDeploy",
		fmt.Sprintf("--username=%s", username), fmt.Sprintf("--password=%s", password))
	if err != nil {
		t.Fatalf("Piper command failed %s", err)
	}

	container.assertHasOutput(t, "running command: cf deploy mta_archives/address-manager_0.0.1.mtar -f")
	container.assertHasOutput(t, "Logged out successfully")
}

func TestCfDeployTypeScriptProject(t *testing.T) {
	t.Parallel()
	username, password := getCredentialsFromEnvironment(t)

	container := givenThisContainer(t, IntegrationTestDockerExecRunnerBundle{
		// The source code for this image is at https://github.com/piper-validation/cloud-s4-sdk-book/tree/validate-ts
		// We use this pre-built image that contains the deployable artifact to avoid
		// a) putting the large file (> 10 mb) into this repo
		// b) avoid the need to build the artifact from source as part of this test
		Image: "ppiper/cloud-foundry-integration-test:ts",
	})

	err := container.whenRunningPiperCommand("cloudFoundryDeploy",
		fmt.Sprintf("--username=%s", username), fmt.Sprintf("--password=%s", password))
	if err != nil {
		t.Fatalf("Piper command failed %s", err)
	}

	container.assertHasOutput(t, "Logged out successfully")
}

func getCredentialsFromEnvironment(t *testing.T) (string, string) {
	log.SetFormatter("plain")
	username := os.Getenv("PIPER_INTEGRATION_CF_USERNAME")
	if len(username) == 0 {
		t.Fatal("Username for SAP Cloud Platform required")
	}
	log.RegisterSecret(username)
	password := os.Getenv("PIPER_INTEGRATION_CF_PASSWORD")
	if len(username) == 0 {
		t.Fatal("Password for SAP Cloud Platform required")
	}
	log.RegisterSecret(password)
	return username, password
}

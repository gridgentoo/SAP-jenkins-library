// +build integration
// can be execute with go test -tags=integration ./integration/...

package main

import (
	"fmt"
	"os"
	"testing"
)

func TestCfDeployMavenProject(t *testing.T) {
	t.Parallel()
	username := os.Getenv("PIPER_INTEGRATION_CF_USERNAME")
	if len(username) == 0 {
		t.Fatal("Username for SAP Cloud Platform required")
	}
	password := os.Getenv("PIPER_INTEGRATION_CF_PASSWORD")
	if len(username) == 0 {
		t.Fatal("Password for SAP Cloud Platform required")
	}
	container := givenThisContainer(t, IntegrationTestDockerExecRunnerBundle{
		Image:   "ppiper/cloud-foundry-integration-test:maven",
		//Environment: map[string]string{"PIPER_parametersJSON": fmt.Sprintf(`{"username": "%s", "password": "%s"}`, username, password)}, //fixme dont write password to console
	})

	err := container.whenRunningPiperCommand("cloudFoundryDeploy", fmt.Sprintf("--username=%s", username), fmt.Sprintf("--password=%s", password)) //fixme dont write password to console
	if err != nil {
		t.Fatalf("Piper command failed %s", err)
	}

	container.assertHasOutput(t, "name:              devops-docker-images-IT")
	container.assertHasOutput(t, "Logged out successfully")
}

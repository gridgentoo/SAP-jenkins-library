package svm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	piperHttp "github.com/SAP/jenkins-library/pkg/http"
	"github.com/sirupsen/logrus"
)

//SVM parameters
type SVM struct {
	ServerURL         string
	Endpoint          string
	ExemptionFileName string
	CredentialsID     string
	BaseURL           string
	Logger            *logrus.Entry
}

//SVMWorkspace the workspace
type SVMWorkspace struct {
	Workspace SVMToken `json:"workspace,omitempty"`
}

//SVMToken the token
type SVMToken struct {
	Token string `json:"token,omitempty"`
}

func (c *SVM) initialize() {

	if len(c.BaseURL) <= 0 {

		if len(c.ServerURL) <= 0 || len(c.Endpoint) <= 0 {
			c.Logger.Fatal("Parameters 'serverURL' and 'svmEndpoint' must be provided as part of the configuration.")
		}
		c.BaseURL = fmt.Sprintf("%v%v/", c.ServerURL, c.Endpoint)
	}
}

//FetchExcemptionFile fetch the excemption file
func (c *SVM) FetchExcemptionFile(targetPath, token string, client *piperHttp.Client) (*io.ReadCloser, error) {

	c.initialize()

	bodyStruct := SVMWorkspace{Workspace: SVMToken{Token: token}}
	targetProperties := fmt.Sprintf("%v,%v", targetPath, c.ExemptionFileName)

	headers := map[string][]string{
		"acceptType": []string{"application/json"},
		"Outputfile": []string{targetProperties},
	}

	c.Logger.Debugf("Fetched exemption file for token %v", token)
	fetchURL := fmt.Sprintf("%v%v", c.BaseURL, "xsjs/assessments/download.xsjs?format=mavenVulas")

	json, err := json.MarshalIndent(bodyStruct, "", "")
	if err != nil {
		return nil, err
	}
	body := strings.NewReader(string(json))

	r, err := client.SendRequest(http.MethodPost, fetchURL, body, headers, nil)
	if err != nil {
		return nil, err
	}

	return &r.Body, nil
}

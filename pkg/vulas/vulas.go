package vulas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	piperHttp "github.com/SAP/jenkins-library/pkg/http"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/sirupsen/logrus"
)

//Vulas ist the vulas client which is used by the step
type Options struct {
	ServerURL       string
	Svm             SVM
	VulasSpaceToken string
	Client          piperHttp.Sender
	BaseURL         string
	Logger          *logrus.Entry
}

//Vulas ist the vulas client which is used by the step
type Vulas struct {
	serverURL       string
	tenantToken     string
	svm             SVM
	vulasSpaceToken string
	vulasSpaceName  string
	client          piperHttp.Sender
	baseURL         string
	logger          *logrus.Entry
}

type SVM struct {
	ServerURL         string
	Endpoint          string
	ExemptionFileName string
	CredentialsId     string
}

type SVMWorkspace struct {
	Workspace SVMToken `json:"workspace,omitempty"`
}

type SVMToken struct {
	Token string `json:"token,omitempty"`
}

type Lookup struct {
	TenantToken string `json:"tenantToken"`
	SpaceName   string `json:"spaceName"`
	SpaceToken  string `json:"spaceToken"`
}

type Vulnerabilities struct {
	VulnScope string `json:"scope, omitempty"`
	VulnType  string `json:"type, omitempty"`
}

type Space struct {
	Name                string          `json:"spaceName"`
	Description         string          `json:"spaceDescription"`
	Owners              string          `json:"spaceOwners"`
	DefaultSpace        string          `json:"default"`
	ExportConfiguration string          `json:"exportConfiguration"`
	Public              bool            `json:"public"`
	Properties          SpaceProperties `json:"properties"`
}

type SpaceProperties struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Value  string `json:"value"`
}

func (c *Vulas) SetOptions(options Options) {
	c.serverURL = options.ServerURL
	c.client = &piperHttp.Client{}

	if options.Logger != nil {
		c.logger = options.Logger
	} else {
		c.logger = log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")
	}

	httpOptions := piperHttp.ClientOptions{Logger: options.Logger}
	c.client.SetOptions(httpOptions)
}

func (c *Vulas) initialize() {

	if len(c.baseURL) <= 0 {

		c.logger = log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")
		if len(c.svm.ServerURL) <= 0 || len(c.svm.Endpoint) <= 0 {
			c.logger.Fatal("Parameters 'serverURL' and 'svmEndpoint' must be provided as part of the configuration.")
		}
		c.baseURL = fmt.Sprintf("%v%v/", c.svm.ServerURL, c.svm.Endpoint)
	}
}

func (c *Vulas) mapToSpace(spaceStr string) *Space {
	spaceObj := new(Space)

	unquoted, err := strconv.Unquote(spaceStr)
	if err != nil {
		err = json.Unmarshal([]byte(spaceStr), spaceObj)
		if err != nil {
			c.logger.WithError(err).Fatalf("Error during unqote response: %v", spaceStr)
		}
	} else {
		err = json.Unmarshal([]byte(unquoted), spaceObj)
	}

	if err != nil {
		c.logger.WithError(err).Fatalf("Error during decode response: %v", spaceStr)
	}
	return spaceObj
}

func (c *Vulas) FetchExcemptionFile(targetPath string) *io.ReadCloser {

	c.initialize()

	bodyStruct := SVMWorkspace{Workspace: SVMToken{Token: c.vulasSpaceToken}}
	targetProperties := fmt.Sprintf("%v,%v", targetPath, c.svm.ExemptionFileName)

	headers := map[string][]string{
		"acceptType": []string{"application/json"},
		"Outputfile": []string{targetProperties},
	}

	c.logger.Debugf("Fetched exemption file for Vulas space %v", c.vulasSpaceToken)
	fetchURL := fmt.Sprintf("%v%v", c.baseURL, "xsjs/assessments/download.xsjs?format=mavenVulas")

	json, err := json.MarshalIndent(bodyStruct, "", "")
	if err != nil {
		c.logger.WithError(err).Fatal("Error during marshal the workspace object")
	}
	body := strings.NewReader(string(json))

	r, err := c.client.SendRequest(http.MethodPost, fetchURL, body, headers, nil)
	if err != nil {
		c.logger.WithError(err).Fatalf("It is not possible to fetch excemption file %v", fetchURL)
	}

	return &r.Body
}

func (c *Vulas) initializeSpaceToken(ppmsID, projectGroup string, space Space) {

	c.initialize()
	errMessage := "[Vulas] Failed to either lookup or create vulas space for "

	if len(c.vulasSpaceToken) > 0 {
		c.logger.Infof("[Vulas] Using space token %v please ensure proper binding to PPMS object %v as part of your workspace configuration in Vulas...", c.vulasSpaceToken, ppmsID)
	} else {
		c.lookupDefaultTenantToken()
		if len(ppmsID) > 0 {
			if len(space.Name) <= 0 {
				space.Name = fmt.Sprintf("PiperVulasSpace_%v", ppmsID)
			}
			if len(space.Description) <= 0 {
				space.Description = fmt.Sprintf("Piper managed Vulas space to scan projects bound to PPMS Object %v", ppmsID)
			}
			c.lookupSpaceByPPMSId(ppmsID, space.Name)
			errMessage += fmt.Sprintf("PPMS object %v...", ppmsID)
		} else {
			if len(space.Name) <= 0 {
				space.Name = fmt.Sprintf("PiperVulasSpace_%v", projectGroup)
			}
			if len(space.Description) <= 0 {
				space.Description = fmt.Sprintf("Piper managed Vulas space to scan projects with group %v", projectGroup)
			}
			c.lookupSpaceByName(space.Name)
			errMessage += fmt.Sprintf("project group %v...", projectGroup)
		}

		// Lookup failed, therefore create a new workspace
		if len(c.vulasSpaceToken) <= 0 {
			c.createSpace(space)
			if len(c.vulasSpaceToken) <= 0 {
				c.logger.Fatal(errMessage)
			}
		}

		c.logger.Debugf("[Vulas] Using space token %v please configure the missing PPMS object binding via config parameter '%v' in Piper", c.vulasSpaceToken, ppmsID)
	}
}

func (c *Vulas) lookupSpaceByPPMSId(ppmsID, spaceName string) {

	c.initialize()

	var parsedResponse []Lookup
	c.httpVulasResult(http.MethodGet, fmt.Sprintf("spaces/search?propertyName=ppmsObjNumber&value=%v", ppmsID), nil, &parsedResponse)

	if len(parsedResponse) == 1 {
		c.vulasSpaceToken = parsedResponse[0].SpaceToken
	} else {

		for _, value := range parsedResponse {
			if value.SpaceName == spaceName {
				c.vulasSpaceToken = value.SpaceToken
			}
		}
	}
	c.logger.Debugf("[Vulas] Successfully looked up space with token %v for PPMS object %v", c.vulasSpaceToken, ppmsID)

}

func (c *Vulas) lookupSpaceByName(spaceName string) {

	c.initialize()

	var parsedResponse []Lookup

	c.httpVulasResult(http.MethodGet, "spaces", nil, &parsedResponse)
	for _, value := range parsedResponse {
		if value.SpaceName == spaceName {
			c.vulasSpaceToken = value.SpaceToken
		}
	}
	c.logger.Debugf("[Vulas] Successfully looked up space with token %v", c.vulasSpaceToken)
}

func (c *Vulas) lookupSpaceNameByToken() {
	c.initialize()

	var parsedResponse Lookup

	c.httpVulasResult(http.MethodGet, fmt.Sprintf("spaces/%v", c.vulasSpaceToken), nil, &parsedResponse)
	c.vulasSpaceName = parsedResponse.SpaceName

	c.logger.Debugf("[Vulas] Successfully looked up space with token %v", c.vulasSpaceToken)
}

func (c *Vulas) lookupVulnerabilities() []Vulnerabilities {
	c.initialize()

	c.lookupSpaceNameByToken()

	url, err := url.Parse(fmt.Sprintf("hubIntegration/apps/%v (%v)/vulndeps", c.vulasSpaceName, c.vulasSpaceToken))
	if err != nil {
		c.logger.WithError(err).Fatal("Malformed URL")
	}

	var parsedResponse []Vulnerabilities
	c.httpVulasResult(http.MethodGet, url.String(), nil, &parsedResponse)

	return parsedResponse
}

func (c *Vulas) lookupVulnerabilitiesByGAV(gav string) []Vulnerabilities {
	c.initialize()

	c.lookupSpaceNameByToken()

	url, err := url.Parse(fmt.Sprintf("hubIntegration/apps/%v (%v)%v/vulndeps", c.vulasSpaceName, c.vulasSpaceToken, gav))
	if err != nil {
		c.logger.WithError(err).Fatal("Malformed URL")
	}

	var parsedResponse []Vulnerabilities
	c.httpVulasResult(http.MethodGet, url.String(), nil, &parsedResponse)

	return parsedResponse
}

func (c *Vulas) lookupDefaultTenantToken() {
	c.initialize()

	if len(c.tenantToken) <= 0 {
		var parsedResponse Lookup
		c.httpVulasResult(http.MethodGet, "tenants/default", nil, &parsedResponse)
		c.tenantToken = parsedResponse.TenantToken
	}
}

func (c *Vulas) createSpace(space Space) {
	c.initialize()

	var parsedResponse Lookup

	json, err := json.MarshalIndent(space, "", "")
	if err != nil {
		c.logger.WithError(err).Fatal("Error during marshal the space object")
	}
	body := strings.NewReader(string(json))

	c.httpVulasResult(http.MethodPost, "spaces", body, &parsedResponse)
	c.vulasSpaceToken = parsedResponse.SpaceToken

	c.logger.Debugf("[Vulas] Successfully created new space with token %v", c.vulasSpaceToken)
}

func (c *Vulas) httpVulasResult(method, path string, body io.Reader, result interface{}) {
	url := fmt.Sprintf("%v%v", c.baseURL, path)
	headers := map[string][]string{
		"acceptType":  []string{"application/json"},
		"contentType": []string{"application/json"},
	}

	if len(c.tenantToken) > 0 {
		headers["X-Vulas-Tenant"] = []string{c.tenantToken}
	}

	r, err := c.client.SendRequest(method, url, body, headers, nil)
	if err != nil {
		c.logger.WithError(err).Fatalf("Error during request %v", url)
	}

	c.mapResponseToStruct(r.Body, result)
}

func (c *Vulas) mapResponseToStruct(r io.ReadCloser, response interface{}) {
	defer r.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	newStr := buf.String()
	if len(newStr) > 0 {

		unquoted, err := strconv.Unquote(newStr)
		if err != nil {
			err = json.Unmarshal([]byte(newStr), response)
			if err != nil {
				c.logger.WithError(err).Fatalf("Error during unqote response: %v", newStr)
			}
		} else {
			err = json.Unmarshal([]byte(unquoted), response)
		}

		if err != nil {
			c.logger.WithError(err).Fatalf("Error during decode response: %v", newStr)
		}
	}
}

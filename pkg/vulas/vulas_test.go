package vulas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	piperHttp "github.com/SAP/jenkins-library/pkg/http"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestFetchExcemptionFileSuccess(t *testing.T) {

	requestURI := ""
	var passedHeaders = map[string][]string{}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		requestURI = req.RequestURI

		passedHeaders = map[string][]string{}
		if req.Header != nil {
			for name, headers := range req.Header {
				passedHeaders[name] = headers
			}
		}

		rw.Write([]byte("OK"))
	}))
	// Close the server when test finishes
	defer server.Close()

	client := &piperHttp.Client{}
	client.SetOptions(piperHttp.ClientOptions{})

	cases := []struct {
		targetPath  string
		svmEndpoint string
		want        string
	}{
		{"targetPath", "/svmEndpoint", "/svmEndpoint/xsjs/assessments/download.xsjs?format=mavenVulas"},
		{"targetPath2", "/svmEndpoint/test/test", "/svmEndpoint/test/test/xsjs/assessments/download.xsjs?format=mavenVulas"},
	}
	for _, c := range cases {

		vc := Vulas{svm: SVM{ServerURL: server.URL, Endpoint: c.svmEndpoint}, client: client, logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")}

		vc.FetchExcemptionFile(c.targetPath)
		assert.Equal(t, requestURI, c.want)
		assert.Contains(t, passedHeaders, "Outputfile")
		assert.Equal(t, passedHeaders["Outputfile"], []string([]string{fmt.Sprintf("%v,", c.targetPath)}))
	}
}

func TestInitializeSpaceToken(t *testing.T) {

	requestURI := ""
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		requestURI = req.RequestURI
		var response interface{}

		if requestURI == "/test/tenants/default" {
			response = Lookup{TenantToken: "lookupDefaultTenantToken"}
		}
		if requestURI == "/test/spaces/search?propertyName=ppmsObjNumber&value=ppmsID" {
			response = []Lookup{Lookup{SpaceName: "unknown", SpaceToken: "unknown"},
				Lookup{SpaceName: "PiperVulasSpace_ppmsID", SpaceToken: "vulasSpaceToken"}}
		}
		if requestURI == "/test/spaces" {
			response = []Lookup{Lookup{SpaceName: "unknown", SpaceToken: "unknown"},
				Lookup{SpaceName: "PiperVulasSpace_projectGroup", SpaceToken: "vulasSpaceToken"}}
		}
		if http.MethodPost == req.Method {
			if requestURI == "/test/spaces" {
				response = Lookup{SpaceName: "PiperVulasSpace_unknown", SpaceToken: "vulasSpaceToken"}
			}
		}

		var b bytes.Buffer
		json.NewEncoder(&b).Encode(&response)
		rw.Write([]byte(b.Bytes()))
	}))
	// Close the server when test finishes
	defer server.Close()

	client := &piperHttp.Client{}
	client.SetOptions(piperHttp.ClientOptions{})

	cases := []struct {
		ppmsID       string
		projectGroup string
		space        Space
		want         string
	}{
		{"ppmsID", "", Space{Name: "", Description: "Description", Owners: "owner", DefaultSpace: "", ExportConfiguration: "", Public: false, Properties: SpaceProperties{Name: "", Source: "", Value: ""}}, "vulasSpaceToken"},
		{"", "projectGroup", Space{Name: "", Description: "Description", Owners: "owner", DefaultSpace: "", ExportConfiguration: "", Public: false, Properties: SpaceProperties{Name: "", Source: "", Value: ""}}, "vulasSpaceToken"},
		{"", "unknown", Space{Name: "", Description: "Description", Owners: "owner", DefaultSpace: "", ExportConfiguration: "", Public: false, Properties: SpaceProperties{Name: "", Source: "", Value: ""}}, "vulasSpaceToken"},
	}
	for _, c := range cases {

		vc := Vulas{svm: SVM{ServerURL: server.URL, Endpoint: "/test"}, client: client, logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")}

		vc.initializeSpaceToken(c.ppmsID, c.projectGroup, c.space)
		assert.Equal(t, vc.vulasSpaceToken, c.want)
	}
}

func TestMapToSpace(t *testing.T) {

	cases := []struct {
		input string
		want  *Space
	}{
		{`"{\"spaceDescription\": \"Description\", \"spaceOwners\": \"owner\"}"`,
			&Space{Name: "", Description: "Description", Owners: "owner", DefaultSpace: "", ExportConfiguration: "", Public: false, Properties: SpaceProperties{Name: "", Source: "", Value: ""}}},
		{`{"spaceDescription": "Description", "spaceOwners": "owner"}`,
			&Space{Name: "", Description: "Description", Owners: "owner", DefaultSpace: "", ExportConfiguration: "", Public: false, Properties: SpaceProperties{Name: "", Source: "", Value: ""}}},
		{"{}", new(Space)},
	}
	for _, c := range cases {

		vc := Vulas{svm: SVM{ServerURL: "dummy", Endpoint: "test"}, logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")}

		got := vc.mapToSpace(c.input)
		assert.Equal(t, c.want, got)
	}
}

func TestLookup(t *testing.T) {

	c := struct {
		lookupSpaceByPPMSId        string
		lookupSpaceByPPMSId2       string
		lookupSpaceByName          string
		lookupSpaceNameByToken     string
		lookupVulnerabilitiesToken string
		lookupVulnerabilities      string
		lookupVulnerabilitiesByGAV string
		lookupDefaultTenantToken   string
		createSpace                string
	}{
		"/test/spaces/search?propertyName=ppmsObjNumber&value=targetPath",
		"/test/spaces/search?propertyName=ppmsObjNumber&value=targetPath2",
		"/test/spaces",
		"/test/spaces/lookupSpaceNameByToken",
		"/test/spaces/lookupVulnerabilities",
		"/test/hubIntegration/apps/lookupVulnerabilities%20%28lookupVulnerabilities%29/vulndeps",
		"/test/hubIntegration/apps/lookupVulnerabilities%20%28lookupVulnerabilities%29lookupVulnerabilitiesByGAV/vulndeps",
		"/test/tenants/default",
		"/test/spaces",
	}

	requestURI := ""
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		requestURI = req.RequestURI

		var response interface{}
		if http.MethodGet == req.Method {
			if requestURI == c.lookupSpaceByPPMSId {
				response = []Lookup{Lookup{SpaceName: "spaceName", SpaceToken: "lookupSpaceByPPMSId1"}}
			} else if requestURI == c.lookupSpaceByPPMSId2 {
				response = []Lookup{Lookup{SpaceName: "unknown", SpaceToken: "unknown"},
					Lookup{SpaceName: "spaceName", SpaceToken: "lookupSpaceByPPMSId2"}}
			} else if requestURI == c.lookupSpaceByName {
				response = []Lookup{Lookup{SpaceName: "spaceName", SpaceToken: "lookupSpaceByName"}}
			} else if requestURI == c.lookupSpaceNameByToken {
				response = Lookup{SpaceName: "lookupSpaceNameByToken", SpaceToken: "spaceToken"}
			} else if requestURI == c.lookupVulnerabilitiesToken {
				response = Lookup{SpaceName: "lookupVulnerabilities", SpaceToken: "spaceToken"}
			} else if requestURI == c.lookupVulnerabilities {
				response = []Vulnerabilities{Vulnerabilities{VulnScope: "scope1", VulnType: "type1"}, Vulnerabilities{VulnScope: "scope2", VulnType: "type2"}}
			} else if requestURI == c.lookupVulnerabilitiesByGAV {
				response = []Vulnerabilities{Vulnerabilities{VulnScope: "scope1", VulnType: "type1"}, Vulnerabilities{VulnScope: "scope2", VulnType: "type2"}}
			} else if requestURI == c.lookupDefaultTenantToken {
				response = Lookup{TenantToken: "lookupDefaultTenantToken"}
			}
		} else if http.MethodPost == req.Method {
			if requestURI == c.createSpace {
				response = Lookup{SpaceName: "spaceName", SpaceToken: "createSpace"}
			}
		}

		var b bytes.Buffer
		json.NewEncoder(&b).Encode(&response)
		rw.Write([]byte(b.Bytes()))
	}))
	// Close the server when test finishes
	defer server.Close()

	client := &piperHttp.Client{}
	client.SetOptions(piperHttp.ClientOptions{})
	vc := Vulas{svm: SVM{ServerURL: server.URL, Endpoint: "/test"}, client: client, logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")}

	t.Run("lookupSpaceByPPMSId 1", func(t *testing.T) {
		vc.lookupSpaceByPPMSId("targetPath", "spaceName")
		assert.Equal(t, c.lookupSpaceByPPMSId, requestURI)
		assert.Equal(t, "lookupSpaceByPPMSId1", vc.vulasSpaceToken)
	})
	t.Run("lookupSpaceByPPMSId 2", func(t *testing.T) {
		vc.lookupSpaceByPPMSId("targetPath2", "spaceName")
		assert.Equal(t, c.lookupSpaceByPPMSId2, requestURI)
		assert.Equal(t, "lookupSpaceByPPMSId2", vc.vulasSpaceToken)
	})

	t.Run("lookupSpaceByPPMSId", func(t *testing.T) {
		vc.lookupSpaceByName("spaceName")
		assert.Equal(t, c.lookupSpaceByName, requestURI)
		assert.Equal(t, "lookupSpaceByName", vc.vulasSpaceToken)
	})

	t.Run("lookupSpaceNameByToken", func(t *testing.T) {
		vc.vulasSpaceToken = "lookupSpaceNameByToken"
		vc.lookupSpaceNameByToken()
		assert.Equal(t, c.lookupSpaceNameByToken, requestURI)
		assert.Equal(t, "lookupSpaceNameByToken", vc.vulasSpaceName)
	})

	t.Run("lookupVulnerabilities", func(t *testing.T) {
		vc.vulasSpaceToken = "lookupVulnerabilities"
		got := vc.lookupVulnerabilities()
		assert.Equal(t, c.lookupVulnerabilities, requestURI)
		assert.Equal(t, "lookupVulnerabilities", vc.vulasSpaceName)
		assert.Equal(t, len(got), 2)
	})
	t.Run("lookupVulnerabilitiesByGAV", func(t *testing.T) {
		vc.vulasSpaceToken = "lookupVulnerabilities"
		got := vc.lookupVulnerabilitiesByGAV("lookupVulnerabilitiesByGAV")
		assert.Equal(t, c.lookupVulnerabilitiesByGAV, requestURI)
		assert.Equal(t, "lookupVulnerabilities", vc.vulasSpaceName)
		assert.Equal(t, len(got), 2)
	})

	t.Run("lookupDefaultTenantToken", func(t *testing.T) {
		vc.lookupDefaultTenantToken()
		assert.Equal(t, c.lookupDefaultTenantToken, requestURI)
		assert.Equal(t, "lookupDefaultTenantToken", vc.tenantToken)
	})
	t.Run("createSpace", func(t *testing.T) {
		space := Space{Name: "SpaceName", Owners: "owner", ExportConfiguration: "AGGREGATED", Public: false, DefaultSpace: "default", Properties: SpaceProperties{Name: "Name"}}

		vc.createSpace(space)
		assert.Equal(t, c.createSpace, requestURI)
		assert.Equal(t, "createSpace", vc.vulasSpaceToken)
	})
}

func TestVulas_CollectMetricsForInflux(t *testing.T) {

	requestURI := ""
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		requestURI = req.RequestURI

		var response interface{}
		if http.MethodGet == req.Method {
			if requestURI == "/test/hubIntegration/apps/lookupSpaceNameByToken%20%28lookupSpaceNameByToken%29GAV1:id1:version1/vulndeps" {
				response = []Vulnerabilities{Vulnerabilities{VulnScope: "PROVIDED", VulnType: "type1", VulnState: 1}, Vulnerabilities{VulnScope: "PROVIDED", VulnType: "type1.1", VulnState: 1, VulnReachable: true}, Vulnerabilities{VulnScope: "IMPORT", VulnType: "type2", VulnState: 2}, Vulnerabilities{VulnScope: "TEST", VulnType: "type3", VulnState: 4}}
			}
			if requestURI == "/test/spaces/lookupSpaceNameByToken" {
				response = Lookup{SpaceName: "lookupSpaceNameByToken", SpaceToken: "spaceToken"}
			}
		}

		var b bytes.Buffer
		json.NewEncoder(&b).Encode(&response)
		rw.Write([]byte(b.Bytes()))
	}))
	// Close the server when test finishes
	defer server.Close()

	client := &piperHttp.Client{}
	client.SetOptions(piperHttp.ClientOptions{})
	vc := Vulas{vulasSpaceToken: "lookupSpaceNameByToken", svm: SVM{ServerURL: server.URL, Endpoint: "/test"}, client: client, logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas")}

	type args struct {
		projectGroup        string
		vulasProjectVersion string
		vulasLookupByGAVs   []string
	}
	tests := []struct {
		name string
		c    *Vulas
		args args
	}{
		{name: "TEST1", c: &vc, args: args{"group1", "version1", []string{"{\"ProjectGroup\": \"GAV1\", \"Artifact\": \"id1\"}"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.c.CollectMetricsForInflux(tt.args.projectGroup, tt.args.vulasProjectVersion, tt.args.vulasLookupByGAVs)
			assert.Equal(t, "4", got["overall"])
			assert.Equal(t, "type1;type1.1;type2;type3;", got["overall_cve"])
			assert.Equal(t, "1", got["reachable"])
			assert.Equal(t, "type1.1;", got["reachable_cve"])
			assert.Equal(t, "2", got["PROVIDED"])
			assert.Equal(t, "type1;type1.1;", got["PROVIDED_cve"])
			assert.Equal(t, "1", got["IMPORT"])
			assert.Equal(t, "type2;", got["IMPORT_cve"])
			assert.Equal(t, "1", got["TEST"])
			assert.Equal(t, "type3;", got["TEST_cve"])
			assert.Equal(t, "2", got["testProvided"])
			assert.Equal(t, "type1;type1.1;", got["testProvided_cve"])
			assert.Equal(t, "1", got["triaged"])
			assert.Equal(t, "type3;", got["triaged_cve"])
			assert.Equal(t, "1", got["vulnerability"])
			assert.Equal(t, "type2;", got["vulnerability_cve"])

		})
	}
}

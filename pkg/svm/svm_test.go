package svm

import (
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
		token       string
		svmEndpoint string
		want        string
	}{
		{"targetPath", "token1", "/svmEndpoint", "/svmEndpoint/xsjs/assessments/download.xsjs?format=mavenVulas"},
		{"targetPath2", "token2", "/svmEndpoint/test/test", "/svmEndpoint/test/test/xsjs/assessments/download.xsjs?format=mavenVulas"},
	}
	for _, c := range cases {

		svm := SVM{ServerURL: server.URL, Endpoint: c.svmEndpoint, Logger: log.Entry().WithField("package", "SAP/jenkins-library/pkg/svm")}

		svm.FetchExcemptionFile(c.targetPath, c.token, client)
		assert.Equal(t, requestURI, c.want)
		assert.Contains(t, passedHeaders, "Outputfile")
		assert.Equal(t, passedHeaders["Outputfile"], []string([]string{fmt.Sprintf("%v,", c.targetPath)}))
	}
}

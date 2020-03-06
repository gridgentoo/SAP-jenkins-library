package cmd

import (
	"reflect"
	"testing"

	"github.com/SAP/jenkins-library/pkg/descriptor"
)

func Test_getProjectVersion(t *testing.T) {

	cases := []struct {
		name            string
		config          vulasExecuteScanOptions
		buildDescriptor descriptor.PyDescriptor
		want            string
	}{
		{"Test 1", vulasExecuteScanOptions{BuildDescriptorFile: "setup.py", VulasVersionMapping: "['setup.py': '0.17']"}, descriptor.PyDescriptor{Version: "1.1.1"}, "0.17"},
		{"Test 1", vulasExecuteScanOptions{BuildDescriptorFile: "setup.py"}, descriptor.PyDescriptor{Version: "1.1.1"}, "1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := getProjectVersion(tt.config, tt.buildDescriptor); got != tt.want {
				t.Errorf("getProjectVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertVersionMappingToMap(t *testing.T) {
	cases := []struct {
		name                string
		vulasVersionMapping string
		want                map[string]string
	}{
		{"Config Example", "['setup.py': '0.17']", map[string]string{"setup.py": "0.17"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertVersionMappingToMap(tt.vulasVersionMapping); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertVersionMappingToMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

package cmd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMavenEvaluateGroupID(t *testing.T) {
	// This is just a temporary test to facilitate debugging
	value, err := evaluateMavenProperty("../pom.xml", "project.groupId")

	assert.NoError(t, err,"expected evaluation to succeed")
	assert.Equal(t, "com.sap.cp.jenkins", value)
}
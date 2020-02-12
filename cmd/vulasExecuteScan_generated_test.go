package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVulasExecuteScanCommand(t *testing.T) {

	testCmd := VulasExecuteScanCommand()

	// only high level testing performed - details are tested in step generation procudure
	assert.Equal(t, "vulasExecuteScan", testCmd.Use, "command name incorrect")

}

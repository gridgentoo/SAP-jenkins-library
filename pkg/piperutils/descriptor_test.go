package piperutils

import (
	"os"
	"os/exec"
	"testing"

	"github.com/SAP/jenkins-library/pkg/command"

	"github.com/stretchr/testify/assert"
)

func helperCommand(command string, s ...string) (cmd *exec.Cmd) {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, s...)
	cmd = exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestGetMavenGAV(t *testing.T) {

	t.Run("test shell", func(t *testing.T) {
		command.ExecCommand = helperCommand
		defer func() { command.ExecCommand = exec.Command }()

		s := command.Command{}

		descriptor, err := GetMavenGAV("./testdata/test_pom.xml", s)

		assert.Nil(t, err)
		assert.Equal(t, descriptor.GroupID, "test.groupID")
		assert.Equal(t, descriptor.ArtifactID, "test-articatID")
		assert.Equal(t, descriptor.Version, "1.0.0")
	})
}

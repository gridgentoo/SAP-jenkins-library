package descriptor

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

		c := command.Command{}

		descriptor, err := GetMavenGAV("./testdata/test_pom.xml", c)

		assert.Nil(t, err)
		assert.Equal(t, "test.groupID", descriptor.GroupID)
		assert.Equal(t, "test-articatID", descriptor.ArtifactID)
		assert.Equal(t, "1.0.0", descriptor.Version)
	})
}

func TestGetPipGAV(t *testing.T) {

	t.Run("test shell", func(t *testing.T) {

		descriptor, err := getPipGAV("./testdata/setup.py")

		assert.Nil(t, err)
		assert.Equal(t, "some-test", descriptor.Name)
		assert.Equal(t, "1.0.0-SNAPSHOT", descriptor.Version)
	})
}

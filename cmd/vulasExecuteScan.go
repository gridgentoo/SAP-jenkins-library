package cmd

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/SAP/jenkins-library/pkg/command"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/piperutils"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/SAP/jenkins-library/pkg/vulas"
)

func vulasExecuteScan(config vulasExecuteScanOptions, telemetryData *telemetry.CustomData, influx *vulasExecuteScanInflux) error {

	c := command.Command{}
	// reroute command output to loging framework
	c.Stdout(log.Entry().Writer())
	c.Stderr(log.Entry().Writer())

	if config.ScanType == "pip" {
		executePipScan(c)
	}

	return nil
}

func createVulasClient(config vulasExecuteScanOptions) vulas.Vulas {

	vc := vulas.Vulas{}

	vulasOptions := vulas.Options{
		ServerURL: config.ServerURL,
		Logger:    log.Entry().WithField("package", "SAP/jenkins-library/pkg/protecode"),
	}

	vc.SetOptions(vulasOptions)

	return vc
}

func executePipScan(cmd command.Command) {
	/*

	 buildDescriptor = utils.getPipGAV(config.buildDescriptorFile)
	                buildDescriptor['group'] = buildDescriptor['artifact']
	                vulasProjectVersion = getProjectVersion(config, buildDescriptor)
	                path = config.buildDescriptorFile.replaceAll('setup.py', '')
	                if (config.pythonCli)
	                    path += "vulas-cli/"
	                vulasReportName = "Vulas Report ${path.replaceFirst('\\./', '')}"
	                config.projectGroup = buildDescriptor['group']
	                if (config.vulasLookupByGAVs != false && !config.vulasLookupByGAVs) config.vulasLookupByGAVs = [].plus(buildDescriptor['artifact'])
	                config.vulasSpaceToken = vulas.initializeSpaceToken()
	                executePythonScan(script, config, svm, vulasProjectVersion, buildDescriptor)

	*/

}

func executePythonScan(config vulasExecuteScanOptions, vulasProjectVersion string, cmd command.Command) {

	var m map[string]string
	buf := new(bytes.Buffer)
	cmd.Stdout(buf)

	//TODO stays on the groovy side
	/*
		dockerExecute(
			script: script,
			dockerImage: config.dockerImage,
			dockerWorkspace: config.dockerWorkspace,
			stashContent: config.stashContent
		) {
	*/

	m["vulas.shared.backend.serviceUrl"] = fmt.Sprintf("%v%v", config.ServerURL, config.BackendEndpoint)

	m["vulas.core.backendConnection"] = "READ_WRITE"
	m["vulas.report.reportDir"] = "target/vulas/report"
	m["vulas.core.appContext.version"] = vulasProjectVersion
	m["vulas.core.app.sourceDir"] = strings.Join(config.PythonSources[:], ",")
	m["vulas.core.app.appPrefixes"] = "com.sap"

	if len(config.VulasSpaceToken) > 0 {
		m["vulas.core.space.token"] = fmt.Sprintf("'%v'", config.VulasSpaceToken)
	}
	if len(config.PpmsID) > 0 {
		m["vulas.report.sap.scv"] = config.PpmsID
	}
	configFileName := "vulas-python.cfg"
	if len(config.PythonCli) > 0 {
		configFileName = "vulas-custom.properties"
		//TODO
		handlePythonCli(config, m, m)
	} else {

		cmd.RunExecutable(fmt.Sprintf("which %v", config.PythonVersion))
		pythonInstallPath := buf.String()
		ifNotNullAddValue(pythonInstallPath, m["vulas.core.bom.python.python"])
	}

	configFileBackup := ""
	copyCommand := ""

	exists, err := piperutils.FileExists(configFileName)
	if err != nil {
		log.Entry().WithError(err).Fatalf("The specified config does not exists (%v)", configFileName)
	}
	if exists {
		configFileBackup = fmt.Sprintf("%v.original", configFileName)
		copyCommand = fmt.Sprintf("cp %v %v\n", configFileName, configFileBackup)

	}
	path := strings.ReplaceAll(config.BuildDescriptorFile, "setup.py", "")

	if len(config.PythonCli) > 0 {

		cmd.RunExecutable(fmt.Sprintf("curl -Ls -o /dev/null -w %v https://github.wdf.sap.corp/vulas/vulas/releases/latest", url_effective))
		releaseUrl := buf.String()
		/*
			def parts = releaseUrl.split("/")
			def version = parts[parts.size() - 1]
			def type = parts[parts.size() - 2]
			def downloadUrl = "https://github.wdf.sap.corp/vulas/vulas/releases/download/${type}/${version}/vulas-cli-${version}.zip"

			fetchExemptionFileFromSVM(config, svm, "${path}vulas-cli/")

			sh """
				cd ${path}
				curl -L -o vulas-cli.zip ${downloadUrl}
				unzip vulas-cli.zip
				${copyCommand}printf \'${options.join('\n')}\n\' ${configFileBackup} > ./vulas-cli/${configFileName}
				cd vulas-cli/app
				find . -wholename **/ /*' -not -type d -and -not -path '*/ //vulas-cli//*' -exec cp -p --parents {} ./vulas-cli/app \\;
		/*${config.pythonInstallCommand}
			  cd ..
			  java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal clean
			  java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal app
			  java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal report
		  """ */
	} else {
		/*
			  fetchExemptionFileFromSVM(config, svm, "${path}")

			  sh """
				  cd ${path}
				  ${copyCommand}printf \'${options.join('\n')}\n\' ${configFileBackup} > ${configFileName}
				  ${config.pythonInstallCommand}
			  """

			  sh "cd ${path} && ${config.pythonVersion} setup.py clean && ${config.pythonVersion} setup.py app && ${config.pythonVersion} setup.py report"
		*/
	}
}

func ifNotNullAddValue(value, result string) {
	if len(value) > 0 {
		result = value
	}
}

func handlePythonCli(config vulasExecuteScanOptions, buildDescriptor map[string]string, m map[string]string) {

	if len(config.PythonSources) == 0 {
		m["vulas.core.app.sourceDir"] = "app"
	} else {
		var pSource string
		for _, pythonSource := range config.PythonSources {
			pSource += fmt.Sprintf("app/%v ,", pythonSource)
		}
		m["vulas.core.app.sourceDir"] = pSource
	}
	m["vulas.core.appContext.group"] = buildDescriptor["group"]
	m["vulas.core.appContext.artifact"] = buildDescriptor["artifact"]
	m["vulas.core.uploadEnabled"] = fmt.Sprintf("%v", true)

	//TODO get installation path for pip
	/*
		            def pipInstallPath = sh script: "which ${config.pip}", returnStdout: true
		            if (pipInstallPath) {
		                options += ["vulas.core.bom.python.pip = ${pipInstallPath}"]
					}
				}
	*/
}

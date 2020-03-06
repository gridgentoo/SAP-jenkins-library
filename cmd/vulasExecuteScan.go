package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SAP/jenkins-library/pkg/command"
	"github.com/SAP/jenkins-library/pkg/descriptor"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/piperutils"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/SAP/jenkins-library/pkg/vulas"
)

func vulasExecuteScan(config vulasExecuteScanOptions, telemetryData *telemetry.CustomData, influx *vulasExecuteScanInflux) error {

	telemetryData.Custom1 = ""
	c := command.Command{}
	// reroute command output to loging framework
	c.Stdout(log.Entry().Writer())
	c.Stderr(log.Entry().Writer())

	vc := createVulasClient(config)

	if config.ScanType == "pip" {
		executePipScan(config, c, vc)
	} else {
		var vulasReportName string
		var vulasProjectVersion string
		buildDescriptor = descriptor.GetMavenGAV(config.buildDescriptorFile, cmd)
		vulasProjectVersion = getProjectVersion(config, buildDescriptor)
		path := strings.ReplaceAll(config.BuildDescriptorFile, "pom.xml", "")
		if config.vulasRunNightly {
			vulasReportName = fmt.Sprintf("Vulas Nightly Report &v", strings.Replace(path, "./", "", 1))
		} else {
			vulasReportName = fmt.Sprintf("Vulas Nightly Report &v", strings.Replace(path, "./", "", 1))
			vulasProjectVersion = fmt.Sprintf("%v-SNAPSHOT")
		}
		config.ProjectGroup = buildDescriptor.GroupID
		if len(config.VulasLookupByGAVs) >= 0 {
			config.VulasLookupByGAVs = append(config.VulasLookupByGAVs, buildDescriptor.ArtifactID)
		}
		// vc.initializeSpaceToken(ppmsID, projectGroup string, space Space) //TODO check parameter
		executeMavenScan(config, vulasProjectVersion, vc)
	}

	return nil
}

func createVulasClient(config vulasExecuteScanOptions) vulas.Vulas {

	vc := vulas.Vulas{}

	vulasOptions := vulas.Options{
		ServerURL: config.ServerURL,
		Logger:    log.Entry().WithField("package", "SAP/jenkins-library/pkg/vulas"),
	}

	vc.SetOptions(vulasOptions)

	return vc
}

func executePipScan(config vulasExecuteScanOptions, cmd command.Command, vc vulas.Vulas) {
	//TODO buildDescriptor := descriptor.getPipGAV(config.BuildDescriptoFile)
	// TODO this is not read from file buildDescriptor['group'] = buildDescriptor['artifact']

	/*

	 buildDescriptor = utils.getPipGAV(config.buildDescriptorFile)
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
	executePythonScan(config, "TODO vulasProjectVersion", cmd, vc)
}

func executePythonScan(config vulasExecuteScanOptions, vulasProjectVersion string, cmd command.Command, vc vulas.Vulas) {

	var m map[string]string
	buf := new(bytes.Buffer)
	cmd.Stdout(buf)

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
		//TODO add right parameter to the function call
		handlePythonCli(config, m, m, cmd)
	} else {
		//runcommand
		cmd.RunShell("/bin/bash", fmt.Sprintf("which %v", config.PythonVersion))
		pythonInstallPath := buf.String()
		ifNotNullAddValue(pythonInstallPath, m["vulas.core.bom.python.python"])
	}

	var configFileBackup string
	var copyCommand string

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
		//runcommand
		cmd.RunShell("/bin/bash", "curl -Ls -o /dev/null -w %{url_effective} https://github.wdf.sap.corp/vulas/vulas/releases/latest")
		releaseURL := buf.String()

		parts := strings.Split(releaseURL, "/")
		version := parts[len(parts)-1]
		vulasType := parts[len(parts)-2]
		downloadURL := fmt.Sprintf("https://github.wdf.sap.corp/vulas/vulas/releases/download/%v/%v/vulas-cli-%v.zip", vulasType, version, version)

		vc.FetchExcemptionFile(fmt.Sprintf("%vvulas-cli/", path))

		cmdString := fmt.Sprintf("cd %v \n ", path)
		cmdString += fmt.Sprintf("curl -L -o vulas-cli.zip %v \n ", downloadURL)
		cmdString += "unzip vulas-cli.zip \n "
		cmdString += fmt.Sprintf("%vprintf '%v\n' %v > ./vulas-cli/%v \n ", copyCommand, m, configFileBackup, configFileName)
		cmdString += "cd vulas-cli/app \n "
		cmdString += "find . -wholename **/ /*' -not -type d -and -not -path '*/ //vulas-cli//*' -exec cp -p --parents {} ./vulas-cli/app \\ \n "
		cmdString += fmt.Sprintf("%v \n ", config.PythonInstallCommand)
		cmdString += "cd .. \n "
		cmdString += fmt.Sprintf("java -jar vulas-cli-%v-jar-with-dependencies.jar -goal clean \n ", version)
		cmdString += fmt.Sprintf("java -jar vulas-cli-%v-jar-with-dependencies.jar -goal app \n ", version)
		cmdString += fmt.Sprintf("java -jar vulas-cli-%v-jar-with-dependencies.jar -goal report", version)
		//runcommand
		cmd.RunShell("/bin/bash", cmdString)

	} else {
		vc.FetchExcemptionFile(path)

		cmdString := fmt.Sprintf("cd %v \n ", path)
		cmdString += fmt.Sprintf("%vprintf '%v\n' %v > %v \n ", copyCommand, m, configFileBackup, configFileName)
		cmdString += fmt.Sprintf("%v \n ", config.PythonInstallCommand)
		cmdString += fmt.Sprintf("cd %v && %v setup.py clean && %v setup.py app && %v setup.py report", path, config.PythonVersion, config.PythonVersion, config.PythonVersion)

		//runcommand
		cmd.RunShell("/bin/bash", cmdString)
	}
}

func ifNotNullAddValue(value, result string) {
	if len(value) > 0 {
		result = value
	}
}

func handlePythonCli(config vulasExecuteScanOptions, buildDescriptor map[string]string, m map[string]string, cmd command.Command) {

	buf := new(bytes.Buffer)
	cmd.Stdout(buf)

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

	var pip string = "pip2"
	if config.PythonVersion == "python3" {
		pip = "pip3"
	}
	cmd.RunShell("/bin/bash", fmt.Sprintf("which %v, returnStdout: true", pip))
	pipInstallPath := buf.String()
	if len(pipInstallPath) > 0 {
		m["vulas.core.bom.python.pip"] = pipInstallPath
	}
}

func executeMavenScan(config vulasExecuteScanOptions, vulasProjectVersion string, vc vulas.Vulas) {

	var options []string
	var scanOptions []string
	var reportOptions []string

	scanOptions = append(scanOptions, "--update-snapshots")
	var command string
	if config.VulasRunNightly {
		command = config.VulasNightlyCommand
		scanOptions = append(scanOptions, fmt.Sprintf("-Dvulas.core.clean.purgeVersions=%v", config.VulasPurgeVersions))
		scanOptions = append(scanOptions, fmt.Sprintf("-Dvulas.core.clean.purgeVersions.keepLast=%v", config.VulasPurgeVersionsKeepLast))
	} else {
		command = config.VulasCycleCommand
	}

	reportOptions = append(reportOptions, "--fail-at-end'")
	reportOptions = append(reportOptions, "-Dvulas") //TODO config.VulasProperty) // default: -Dvulas
	reportOptions = append(reportOptions, "-Dvulas.report.overridePomVersion=true")

	options = append(options, fmt.Sprintf("--settings %v", "MvnSettingsFile")) // TODO config.MvnSettingsFile))
	options = append(options, "-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn")
	options = append(options, "--batch-mode")
	options = append(options, fmt.Sprintf("file %v", config.BuildDescriptorFile))
	options = append(options, fmt.Sprintf("-Dvulas.core.appContext.version=%v", vulasProjectVersion))
	options = append(options, fmt.Sprintf("-Dvulas.shared.backend.serviceUrl=%v%v", config.ServerURL, config.BackendEndpoint))

	if len(config.VulasSpaceToken) > 0 {
		options = append(options, fmt.Sprintf("-Dvulas.core.space.token='%v'", config.VulasSpaceToken))
	}
	if len(config.PpmsID) > 0 {
		options = append(options, fmt.Sprintf("-Dvulas.report.sap.scv='%v'", config.PpmsID))
	}

	if len(command) > 0 {
		command = command
	}
	/*
		//TODO stays on groovy side
		    dockerExecute(
		        script: script,
		        dockerImage: config.dockerImage,
		        dockerWorkspace: config.dockerWorkspace,
		        stashContent: config.stashContent
		    ) {
		        //write settings.xml file that knows about the staging repo as well as the standard repos of nexus
		        utils.rewriteSettings(this, config.artifactUrl, config.mvnSettingsFile, "${config.dockerWorkspace}/.m2/settings.xml")

		        fetchExemptionFileFromSVM(config, svm)

		        sh "mvn ${options.plus(scanOptions).join(' ')} ${command}"
		        sh "mvn ${options.plus(reportOptions).join(' ')} ${config.vulasPlugin}:report"
		    }
		    return vulasProjectVersion
		}h
	*/
}

func reportDataToInflux(m map[string]string, influx *vulasExecuteScanInflux) {

	influx.vulas_data.fields.overall = m["overall"]
	influx.vulas_data.fields.overall_cve = m["overall_cve"]
	influx.vulas_data.fields.proved_reachable = m["proved_reachable"]
	influx.vulas_data.fields.proved_reachable_cve = m["proved_reachable_cve"]
	influx.vulas_data.fields.vulnerabilities = m["vulnerabilities"]
	influx.vulas_data.fields.vulnerabilities_cve = m["vulnerabilities_cve"]
	influx.vulas_data.fields.triaged_vulnerabilities = m["triaged_vulnerabilities"]
	influx.vulas_data.fields.triaged_vulnerabilities_cve = m["triaged_vulnerabilities_cve"]
	influx.vulas_data.fields.testProvided_vulnerabilities = m["testProvided_vulnerabilities"]
	influx.vulas_data.fields.testProvided_vulnerabilities_cve = m["testProvided_vulnerabilities_cve"]

	//was befor dynamic
	influx.vulas_data.fields.IMPORT = m["IMPORT"]
	influx.vulas_data.fields.IMPORT_cve = m["IMPORT_cve"]
	influx.vulas_data.fields.SYSTEM = m["SYSTEM"]
	influx.vulas_data.fields.SYSTEM_cve = m["SYSTEM_cve"]
	influx.vulas_data.fields.TEST = m["TEST"]
	influx.vulas_data.fields.TEST_cve = m["TEST_cve"]
	influx.vulas_data.fields.RUNTIME = m["RUNTIME"]
	influx.vulas_data.fields.RUNTIME_cve = m["RUNTIME_cve"]
	influx.vulas_data.fields.PROVIDED = m["PROVIDED"]
	influx.vulas_data.fields.PROVIDED_cve = m["PROVIDED_cve"]
	influx.vulas_data.fields.COMPILE = m["COMPILE"]
	influx.vulas_data.fields.COMPILE_cve = m["COMPILE_cve"]
}

func getProjectVersion(config vulasExecuteScanOptions, buildDescriptor descriptor.Descriptor) string {
	var version string
	// load version from version mapping
	if len(config.VulasVersionMapping) > 0 {

		m := convertVersionMappingToMap(config.VulasVersionMapping)

		var versionBuildDescriptor string
		versionBuildDescriptor = config.BuildDescriptorFile
		if len(versionBuildDescriptor) > 0 {
			if len(m[versionBuildDescriptor]) > 0 {
				version = m[versionBuildDescriptor]
			}
		}
	}

	// load version from buildDescriptor file
	if len(version) <= 0 {
		version = strings.Split(buildDescriptor.GetVersion(), ".")[0]
	}

	return version
}

func convertVersionMappingToMap(vulasVersionMapping string) map[string]string {

	m := make(map[string]string)

	valueJSON := strings.Replace(vulasVersionMapping, "[", "{", -1)
	valueJSON = strings.Replace(valueJSON, "]", "}", -1)
	valueJSON = strings.Replace(valueJSON, "\"", "`", -1)
	valueJSON = strings.Replace(valueJSON, "'", "\"", -1)

	if err := json.Unmarshal([]byte(valueJSON), &m); err != nil {
		log.Entry().WithError(err).Fatal("error during decoding the VulasVersionMapping")
	}

	return m
}

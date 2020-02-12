package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SAP/jenkins-library/pkg/config"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/piperenv"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/spf13/cobra"
)

type vulasExecuteScanOptions struct {
	PythonVersion              string   `json:"pythonVersion,omitempty"`
	BuildDescriptorFile        string   `json:"buildDescriptorFile,omitempty"`
	SvmEndpoint                string   `json:"svmEndpoint,omitempty"`
	VulasVersionMapping        string   `json:"vulasVersionMapping,omitempty"`
	SvmServerURL               string   `json:"svmServerUrl,omitempty"`
	VulasNightlySchedule       string   `json:"vulasNightlySchedule,omitempty"`
	Space                      string   `json:"space,omitempty"`
	BackendEndpoint            string   `json:"backendEndpoint,omitempty"`
	VulasLookupByGAVs          string   `json:"vulasLookupByGAVs,omitempty"`
	VulasPlugin                string   `json:"vulasPlugin,omitempty"`
	ServerURL                  string   `json:"serverUrl,omitempty"`
	ArtifactURL                string   `json:"artifactUrl,omitempty"`
	VulasPurgeVersions         bool     `json:"vulasPurgeVersions,omitempty"`
	VulasCycleCommand          string   `json:"vulasCycleCommand,omitempty"`
	VulasPurgeVersionsKeepLast string   `json:"vulasPurgeVersionsKeepLast,omitempty"`
	PythonCli                  string   `json:"pythonCli,omitempty"`
	PythonSources              []string `json:"pythonSources,omitempty"`
	VulasNightlyCommand        string   `json:"vulasNightlyCommand,omitempty"`
	BuildDescriptorExcludeList string   `json:"buildDescriptorExcludeList,omitempty"`
	SvmExemptionFileName       string   `json:"svmExemptionFileName,omitempty"`
	VulasRunNightly            string   `json:"vulasRunNightly,omitempty"`
	VulasSpaceToken            string   `json:"vulasSpaceToken,omitempty"`
	PythonInstallCommand       string   `json:"pythonInstallCommand,omitempty"`
	ScanType                   string   `json:"scanType,omitempty"`
	PpmsID                     string   `json:"ppmsID,omitempty"`
}

type vulasExecuteScanInflux struct {
	vulas_data struct {
		fields struct {
			overall_cve                      string
			proved_reachable                 string
			proved_reachable_cve             string
			vulnerabilities                  string
			vulnerabilities_cve              string
			triaged_vulnerabilities          string
			triaged_vulnerabilities_cve      string
			testProvided_vulnerabilities     string
			testProvided_vulnerabilities_cve string
		}
		tags struct {
		}
	}
}

func (i *vulasExecuteScanInflux) persist(path, resourceName string) {
	measurementContent := []struct {
		measurement string
		valType     string
		name        string
		value       string
	}{
		{valType: config.InfluxField, measurement: "vulas_data", name: "overall_cve", value: i.vulas_data.fields.overall_cve},
		{valType: config.InfluxField, measurement: "vulas_data", name: "proved_reachable", value: i.vulas_data.fields.proved_reachable},
		{valType: config.InfluxField, measurement: "vulas_data", name: "proved_reachable_cve", value: i.vulas_data.fields.proved_reachable_cve},
		{valType: config.InfluxField, measurement: "vulas_data", name: "vulnerabilities", value: i.vulas_data.fields.vulnerabilities},
		{valType: config.InfluxField, measurement: "vulas_data", name: "vulnerabilities_cve", value: i.vulas_data.fields.vulnerabilities_cve},
		{valType: config.InfluxField, measurement: "vulas_data", name: "triaged_vulnerabilities", value: i.vulas_data.fields.triaged_vulnerabilities},
		{valType: config.InfluxField, measurement: "vulas_data", name: "triaged_vulnerabilities_cve", value: i.vulas_data.fields.triaged_vulnerabilities_cve},
		{valType: config.InfluxField, measurement: "vulas_data", name: "testProvided_vulnerabilities", value: i.vulas_data.fields.testProvided_vulnerabilities},
		{valType: config.InfluxField, measurement: "vulas_data", name: "testProvided_vulnerabilities_cve", value: i.vulas_data.fields.testProvided_vulnerabilities_cve},
	}

	errCount := 0
	for _, metric := range measurementContent {
		err := piperenv.SetResourceParameter(path, resourceName, filepath.Join(metric.measurement, fmt.Sprintf("%vs", metric.valType), metric.name), metric.value)
		if err != nil {
			log.Entry().WithError(err).Error("Error persisting influx environment.")
			errCount++
		}
	}
	if errCount > 0 {
		os.Exit(1)
	}
}

// VulasExecuteScanCommand Vulas is a program analysis tool that helps you identify, assess and mitigate vulnerabilities in the open-source dependencies of Java and Python applications.
func VulasExecuteScanCommand() *cobra.Command {
	metadata := vulasExecuteScanMetadata()
	var stepConfig vulasExecuteScanOptions
	var startTime time.Time
	var influx vulasExecuteScanInflux

	var createVulasExecuteScanCmd = &cobra.Command{
		Use:   "vulasExecuteScan",
		Short: "Vulas is a program analysis tool that helps you identify, assess and mitigate vulnerabilities in the open-source dependencies of Java and Python applications.",
		Long: `Vulas is a program analysis tool that helps you identify, assess and mitigate vulnerabilities in the open-source dependencies of Java and Python applications.
In future it is planned to support even more programming languages i.e. Javascript with this tool. For a full list of supported and recommended languages
please have a look at the [OS3 JAM Tools Overview Page](https://jam4.sapjam.com/groups/XgeUs0CXItfeWyuI4k7lM3/overview_page/VpPnhWUTipYV4eg57rSmXk).

!!! info
    Please update your Vulas version to the most recent [release](https://github.com/SAP/vulnerability-assessment-tool/releases).

Piper is an opinionated CI/CD pipeline framework allowing you to handle the SAP Product Standard requirements throughout you software delivery process in an automated fashion.
Vulas is a SAP internal tool to detect vulnerable Free and Open Source (FOSS) software components being used in your product. As a unique capability it cannot just simply detect the
FOSS component but it is actually able to analyse into your specific usage scenario and can therefore provide additional insights whether the contained vulnerabilities would be reachable through your application.
This can be specifically helpful in a situation where you can not simply get rid of a vulnerability by updating to the latest version of the FOSS affected.
May it be due to the fact that no fix has been provided by the community yet or may it be that you cannot simply update due to potential incompatibilities of your code in related to the version providing the fix.

Since these kind of in-depth scans take way more time than a simple detection of the affected library version Piper can create a scheduled pipeline run by setting ` + "`" + `runNightly: true` + "`" + ` as part of the ` + "`" + `setupPipelineEnvironment` + "`" + ` step configuration
and setting ` + "`" + `vulasRunNightly` + "`" + ` on step ` + "`" + `executeVulasScan` + "`" + ` in addition. Doing so enables Vulas reachability analysis within Piper on a nightly basis and reports it into the Vulas backend into a version named ` + "`" + `<major-version-of-your-module>` + "`" + ` so
if your currently declared version in the ` + "`" + `pom.xml` + "`" + ` would be ` + "`" + `1.2.3` + "`" + ` the version used for nightly scans would be ` + "`" + `1` + "`" + ` whereas the continuous scans that happen an any merge/commit to master
would report in a version ` + "`" + `<major-version-of-your-module>-SNAPSHOT` + "`" + `.

The overall idea of the process would be that once:

**Scenario 1**

* a merge commit happens and the pipeline fails on Vulas with vulnerabilities of CVSS >= 7 being detected
* you may simply remove or update the related component(s) based on what is a working solution for your scenario - usually the later
* your changes are committed to master and trigger a new run, vulnerabilities are gone and Vulas or overall pipeline succeeds

**Scenario 2**

* a merge commit happens and the pipeline fails on Vulas with vulnerabilities of CVSS >= 7 being detected
* you can neither remove or update the related component(s)
* you may temporarily exclude the CVEs from failing the pipeline until you were able to review the results of the next nightly run
* depending on the detailed result provided by the nightly run you could consider to leave the exclusions in since they show not to be reachable
* in case there is any evidence on the reachability you need consider counter measures like replacing the FOSS with a non-vulnerable alternative, replacing the functionality
  with your own non-vulnerable code, contacting [Phosphor team](https://wiki.wdf.sap.corp/wiki/display/osssec/Phosphor) on the availability of a patched version
  of your FOSS or the willingness to do this job for you or finally you patching the FOSS under consideration of license restrictions and obligations.

Whenever you look at nightly results of Vulas please cross-check them manually and consider aspects like the test coverage of your code.
Depending on that you can (de-)stabilize your gut feeling on how reliable the Vulas runtime detection results are.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			startTime = time.Now()
			log.SetStepName("vulasExecuteScan")
			log.SetVerbose(GeneralConfig.Verbose)
			return PrepareConfig(cmd, &metadata, "vulasExecuteScan", &stepConfig, config.OpenPiperFile)
		},
		Run: func(cmd *cobra.Command, args []string) {
			telemetryData := telemetry.CustomData{}
			telemetryData.ErrorCode = "1"
			handler := func() {
				influx.persist(GeneralConfig.EnvRootPath, "influx")
				telemetryData.Duration = fmt.Sprintf("%v", time.Since(startTime).Milliseconds())
				telemetry.Send(&telemetryData)
			}
			log.DeferExitHandler(handler)
			defer handler()
			telemetry.Initialize(GeneralConfig.NoTelemetry, "vulasExecuteScan")
			vulasExecuteScan(stepConfig, &telemetryData, &influx)
			telemetryData.ErrorCode = "0"
		},
	}

	addVulasExecuteScanFlags(createVulasExecuteScanCmd, &stepConfig)
	return createVulasExecuteScanCmd
}

func addVulasExecuteScanFlags(cmd *cobra.Command, stepConfig *vulasExecuteScanOptions) {
	cmd.Flags().StringVar(&stepConfig.PythonVersion, "pythonVersion", "python3", "The Python version to be used, either `'python2'` or `'python3'`")
	cmd.Flags().StringVar(&stepConfig.BuildDescriptorFile, "buildDescriptorFile", os.Getenv("PIPER_buildDescriptorFile"), "Path to the build descriptor file addressing the module/folder to be scanned. Defaults are for scanType=`maven`: `./pom.xml`, scanType=`pip`: `./setup.py`, scanType=`mta`: determined automatically")
	cmd.Flags().StringVar(&stepConfig.SvmEndpoint, "svmEndpoint", "/SVM/services", "The REST API endpoint of the SVM server")
	cmd.Flags().StringVar(&stepConfig.VulasVersionMapping, "vulasVersionMapping", os.Getenv("PIPER_vulasVersionMapping"), "A map i.e. `['setup.py': '0.17']` to support overrides of versions reported into the Vulas backend. The key of each of the entries is the workspace-relative path to the build descriptor and the value is the version string to be used for reporting")
	cmd.Flags().StringVar(&stepConfig.SvmServerURL, "svmServerUrl", "https://svmprodw8563e4f1.int.sap.hana.ondemand.com", "The URL of the SVM server")
	cmd.Flags().StringVar(&stepConfig.VulasNightlySchedule, "vulasNightlySchedule", os.Getenv("PIPER_vulasNightlySchedule"), "")
	cmd.Flags().StringVar(&stepConfig.Space, "space", "map[exportConfiguration:AGGREGATED owners:[] public:true]", "`space:`<br/>&nbsp;&nbsp;`exportConfiguration: 'AGGREGATED'`<br/>&nbsp;&nbsp;`public: true`<br/>&nbsp;&nbsp;`owners: []`|Parameters used to created spaces on the fly. Allowed values for `exportConfiguration` are `'AGGREGATED'`, `'OFF'`, `'DEFAULT'` and `owners` should be filled with one or several email addresses, ideally a DL that feels responsible for this workspace")
	cmd.Flags().StringVar(&stepConfig.BackendEndpoint, "backendEndpoint", "/backend", "Endpoint of the Vulas backend used for any REST API calls")
	cmd.Flags().StringVar(&stepConfig.VulasLookupByGAVs, "vulasLookupByGAVs", os.Getenv("PIPER_vulasLookupByGAVs"), "list of ArtifactIds to be looked up")
	cmd.Flags().StringVar(&stepConfig.VulasPlugin, "vulasPlugin", "com.sap.research.security.vulas:plugin-maven", "The version of the Vulas Maven plugin used for scanning")
	cmd.Flags().StringVar(&stepConfig.ServerURL, "serverUrl", "https://vulas.c.eu-de-2.cloud.sap", "The Vulas server URL")
	cmd.Flags().StringVar(&stepConfig.ArtifactURL, "artifactUrl", os.Getenv("PIPER_artifactUrl"), "URL pointing to the artifact in the staging repo, usually auto-configured by the pipeline")
	cmd.Flags().BoolVar(&stepConfig.VulasPurgeVersions, "vulasPurgeVersions", true, "Whether old versions of the scanned artifact should be purged/deleted in the Vulas backend.")
	cmd.Flags().StringVar(&stepConfig.VulasCycleCommand, "vulasCycleCommand", "-DskipTests ${vulasProperty} ${vulasPlugin}:clean compile ${vulasPlugin}:app install", "The command used to execute the Maven scan for every commit to the relevant branch")
	cmd.Flags().StringVar(&stepConfig.VulasPurgeVersionsKeepLast, "vulasPurgeVersionsKeepLast", "5", "The numnber of versions to be kept starting from the most recent ones")
	cmd.Flags().StringVar(&stepConfig.PythonCli, "pythonCli", os.Getenv("PIPER_pythonCli"), "Whether the Vulas Python CLI is to used for scanning")
	cmd.Flags().StringSliceVar(&stepConfig.PythonSources, "pythonSources", []string{""}, "The list of source directories which will be added to Vulas scan config in case of a Python scan")
	cmd.Flags().StringVar(&stepConfig.VulasNightlyCommand, "vulasNightlyCommand", "-T 1C -Dmaven.test.failure.ignore=true -Djacoco.skip=true ${vulasProperty} ${vulasPlugin}:clean compile ${vulasPlugin}:app ${vulasPlugin}:a2c ${vulasPlugin}:prepare-vulas-agent install ${vulasPlugin}:upload ${vulasPlugin}:t2c", "The command used to execute the Maven scan performing a reachability analysis")
	cmd.Flags().StringVar(&stepConfig.BuildDescriptorExcludeList, "buildDescriptorExcludeList", os.Getenv("PIPER_buildDescriptorExcludeList"), "Build descriptor files to exclude modules from being scanned")
	cmd.Flags().StringVar(&stepConfig.SvmExemptionFileName, "svmExemptionFileName", "vulas-exemptionsFromSvm.properties", "The name used to create the Vulas properties file")
	cmd.Flags().StringVar(&stepConfig.VulasRunNightly, "vulasRunNightly", os.Getenv("PIPER_vulasRunNightly"), "Defines which kind of scan is being executed. When setting it to `true` and running manual or scheduled scans a reachability analysis will be performed whereas `false` will do a simple detection on the library level. Setting `true` on a build triggered by an SCM change will *not* switch to always performing a reachability analysis to allow the pipeline to automatically alternate between library level and reachability analysis. When staying with the default value `false` only library detection will happen, so to opt-in for reachability analysis - the former default - you need to set `true`.")
	cmd.Flags().StringVar(&stepConfig.VulasSpaceToken, "vulasSpaceToken", os.Getenv("PIPER_vulasSpaceToken"), "The token of the workspace created in the Vulas backend, if not provided Piper will try to manage the workspace based on the `ppmsID` or the group ID of the project being analysed")
	cmd.Flags().StringVar(&stepConfig.PythonInstallCommand, "pythonInstallCommand", "${pip} install --user --upgrade --index-url http://nexus.wdf.sap.corp:8081/nexus/content/groups/build.snapshots.pypi/simple/ --trusted-host nexus.wdf.sap.corp --no-cache-dir setuptools vulas-plugin-setuptools .", "The additional install command issued to initialize the Python environment")
	cmd.Flags().StringVar(&stepConfig.ScanType, "scanType", "maven", "The type of scan to execute which can be `'maven'`, `'pip'`, or `'mta'`")
	cmd.Flags().StringVar(&stepConfig.PpmsID, "ppmsID", os.Getenv("PIPER_ppmsID"), "PPMS Object Number of the Software Conmponent Version the pipeline's build artifact correlates to")

}

// retrieve step metadata
func vulasExecuteScanMetadata() config.StepData {
	var theMetaData = config.StepData{
		Spec: config.StepSpec{
			Inputs: config.StepInputs{
				Parameters: []config.StepParameters{
					{
						Name:        "pythonVersion",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"GENERAL", "PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "buildDescriptorFile",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "svmEndpoint",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasVersionMapping",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "svmServerUrl",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasNightlySchedule",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "space",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "backendEndpoint",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasLookupByGAVs",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasPlugin",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "serverUrl",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "artifactUrl",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasPurgeVersions",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "bool",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasCycleCommand",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasPurgeVersionsKeepLast",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "pythonCli",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "pythonSources",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "[]string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasNightlyCommand",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "buildDescriptorExcludeList",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"GENERAL", "PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "svmExemptionFileName",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasRunNightly",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "vulasSpaceToken",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "pythonInstallCommand",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "scanType",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
					{
						Name:        "ppmsID",
						ResourceRef: []config.ResourceReference{},
						Scope:       []string{"GENERAL", "PARAMETERS", "STAGES", "STEPS"},
						Type:        "string",
						Mandatory:   false,
						Aliases:     []config.Alias{},
					},
				},
			},
		},
	}
	return theMetaData
}

import com.cloudbees.groovy.cps.NonCPS
import com.sap.piper.GenerateDocumentation
import com.sap.piper.internal.Deprecate
import com.sap.piper.internal.JenkinsUtils
import com.sap.icd.jenkins.Utils
import com.sap.piper.internal.ConfigurationHelper
import com.sap.piper.internal.Notify
import com.sap.piper.internal.integration.SoftwareVulnerabilityMonitor
import com.sap.piper.internal.integration.Vulas
import com.sap.piper.internal.mta.MtaMultiplexer

import groovy.transform.Field
import groovy.text.GStringTemplateEngine
import hudson.AbortException

import static com.sap.piper.internal.Prerequisites.checkScript

@Field String STEP_NAME = 'executeVulasScan'
@Field Set GENERAL_CONFIG_KEYS = [
    /** Build descriptor files to exclude modules from being scanned */
    'buildDescriptorExcludeList',
    /** PPMS Object Number of the Software Conmponent Version the pipeline's build artifact correlates to */
    'ppmsID',
    /** The Python version to be used, either `'python2'` or `'python3'` */
    'pythonVersion',
    /**
     * Whether the step should provide detailed logging
     * @possibleValues `true`, `false`
     **/
    'verbose'
]
@Field Set STEP_CONFIG_KEYS = GENERAL_CONFIG_KEYS.plus([
    /** URL pointing to the artifact in the staging repo, usually auto-configured by the pipeline */
    'artifactUrl',
    /** Endpoint of the Vulas backend used for any REST API calls */
    'backendEndpoint',
    /**
     * Path to the build descriptor file addressing the module/folder to be scanned.
     * Defaults are for scanType=`maven`: `./pom.xml`, scanType=`pip`: `./setup.py`, scanType=`mta`: determined automatically
     **/
    'buildDescriptorFile',
    /** Docker image to be used for scanning */
    'dockerImage',
    /** Docker workspace to be used for scanning */
    'dockerWorkspace',
    /**
     * Whether the Vulas Python CLI is to used for scanning
     * @possibleValues `true`, `false`
     **/
    'pythonCli',
    /** The additional install command issued to initialize the Python environment */
    'pythonInstallCommand',
    /** The list of source directories which will be added to Vulas scan config in case of a Python scan */
    'pythonSources',
    /** The type of scan to execute which can be `'maven'`, `'pip'`, or `'mta'` */
    'scanType',
    /** The Vulas server URL */
    'serverUrl',
    /** The stash content to be used for populating the workspace */
    'stashContent',
    /**
     * The credentials used to download the [Vulas exemption file from the Software Vulnerability Monitor (SVM)](https://wiki.wdf.sap.corp/wiki/display/osssec/Technical+User+generation+for+Vulas+Exemptions).
     * When enabling this feature, please make sure to remove the `vulas.report.exceptionExcludeBugs` and respective audit properties from the Vulas configuration file residing in your repository. Otherwise
     * the newly maintained exemptions from SVM might be ignored. Your previously maintained audits are already part of the exemption file being downloaded from SVM so there is not additional migration requirement.
     * Please do not simply delete your existing `vulas-custom.properties` file unless you have ensured that it does not supply any additional configurations/customizations to the Vulas scan and has only been used
     * to exempt findings.
     **/
    'svmCredentialsId',
    /** The URL of the SVM server */
    'svmServerUrl',
    /** The REST API endpoint of the SVM server */
    'svmEndpoint',
    /** The name used to create the Vulas properties file */
    'svmExemptionFileName',
    /** The command used to execute the Maven scan for every commit to the relevant branch */
    'vulasCycleCommand',
    /** The command used to execute the Maven scan performing a reachability analysis */
    'vulasNightlyCommand',
    'vulasNightlySchedule',
    /** The version of the Vulas Maven plugin used for scanning */
    'vulasPlugin',
    /**
     * Whether old versions of the scanned artifact should be purged/deleted in the Vulas backend.
     * @possibleValues `true`, `false`
     **/
    'vulasPurgeVersions',
    /** The numnber of versions to be kept starting from the most recent ones */
    'vulasPurgeVersionsKeepLast',
    /**
     * Defines which kind of scan is being executed. When setting it to `true` and running manual or scheduled scans a reachability analysis will be performed whereas `false` will do a simple detection on the library level.
     * Setting `true` on a build triggered by an SCM change will *not* switch to always performing a reachability analysis to allow the pipeline to automatically alternate between library level and reachability analysis. When
     * staying with the default value `false` only library detection will happen, so to opt-in for reachability analysis - the former default - you need to set `true`.
     * @possibleValues `true`, `false`
     **/
    'vulasRunNightly',
    /** A map i.e. `['setup.py': '0.17']` to support overrides of versions reported into the Vulas backend. The key of each of the entries is the workspace-relative path to the build descriptor and the value is the version string to be used for reporting */
    'vulasVersionMapping',
    /** The token of the workspace created in the Vulas backend, if not provided Piper will try to manage the workspace based on the `ppmsID` or the group ID of the project being analysed */
    'vulasSpaceToken',
    /** list of ArtifactIds to be looked up */
    'vulasLookupByGAVs',
    /**
     * `space:`<br/>&nbsp;&nbsp;`exportConfiguration: 'AGGREGATED'`<br/>&nbsp;&nbsp;`public: true`<br/>&nbsp;&nbsp;`owners: []`|Parameters used to created spaces on the fly.
     * Allowed values for `exportConfiguration` are `'AGGREGATED'`, `'OFF'`, `'DEFAULT'` and `owners` should be filled with one or several email addresses,
     * ideally a DL that feels responsible for this workspace
     */
    'space'
])
@Field Set PARAMETER_KEYS = STEP_CONFIG_KEYS

/**
 * Vulas is a program analysis tool that helps you identify, assess and mitigate vulnerabilities in the open-source dependencies of Java and Python applications.
 * In future it is planned to support even more programming languages i.e. Javascript with this tool. For a full list of supported and recommended languages
 * please have a look at the [OS3 JAM Tools Overview Page](https://jam4.sapjam.com/groups/XgeUs0CXItfeWyuI4k7lM3/overview_page/VpPnhWUTipYV4eg57rSmXk).
 *
 * !!! info
 *     Please update your Vulas version to the most recent [release](https://github.com/SAP/vulnerability-assessment-tool/releases).
 *
 * Piper is an opinionated CI/CD pipeline framework allowing you to handle the SAP Product Standard requirements throughout you software delivery process in an automated fashion.
 * Vulas is a SAP internal tool to detect vulnerable Free and Open Source (FOSS) software components being used in your product. As a unique capability it cannot just simply detect the
 * FOSS component but it is actually able to analyse into your specific usage scenario and can therefore provide additional insights whether the contained vulnerabilities would be reachable through your application.
 * This can be specifically helpful in a situation where you can not simply get rid of a vulnerability by updating to the latest version of the FOSS affected.
 * May it be due to the fact that no fix has been provided by the community yet or may it be that you cannot simply update due to potential incompatibilities of your code in related to the version providing the fix.
 *
 * Since these kind of in-depth scans take way more time than a simple detection of the affected library version Piper can create a scheduled pipeline run by setting `runNightly: true` as part of the `setupPipelineEnvironment` step configuration
 * and setting `vulasRunNightly` on step `executeVulasScan` in addition. Doing so enables Vulas reachability analysis within Piper on a nightly basis and reports it into the Vulas backend into a version named `<major-version-of-your-module>` so
 * if your currently declared version in the `pom.xml` would be `1.2.3` the version used for nightly scans would be `1` whereas the continuous scans that happen an any merge/commit to master
 * would report in a version `<major-version-of-your-module>-SNAPSHOT`.
 *
 * The overall idea of the process would be that once:
 *
 * **Scenario 1**
 *
 * * a merge commit happens and the pipeline fails on Vulas with vulnerabilities of CVSS >= 7 being detected
 * * you may simply remove or update the related component(s) based on what is a working solution for your scenario - usually the later
 * * your changes are committed to master and trigger a new run, vulnerabilities are gone and Vulas or overall pipeline succeeds
 *
 * **Scenario 2**
 *
 * * a merge commit happens and the pipeline fails on Vulas with vulnerabilities of CVSS >= 7 being detected
 * * you can neither remove or update the related component(s)
 * * you may temporarily exclude the CVEs from failing the pipeline until you were able to review the results of the next nightly run
 * * depending on the detailed result provided by the nightly run you could consider to leave the exclusions in since they show not to be reachable
 * * in case there is any evidence on the reachability you need consider counter measures like replacing the FOSS with a non-vulnerable alternative, replacing the functionality
 *   with your own non-vulnerable code, contacting [Phosphor team](https://wiki.wdf.sap.corp/wiki/display/osssec/Phosphor) on the availability of a patched version
 *   of your FOSS or the willingness to do this job for you or finally you patching the FOSS under consideration of license restrictions and obligations.
 *
 * Whenever you look at nightly results of Vulas please cross-check them manually and consider aspects like the test coverage of your code.
 * Depending on that you can (de-)stabilize your gut feeling on how reliable the Vulas runtime detection results are.
 */
@GenerateDocumentation
void call(Map parameters = [:]) {
    handlePipelineStepErrors (stepName: STEP_NAME, stepParameters: parameters,
        libraryDocumentationUrl: 'https://github.wdf.sap.corp/pages/ContinuousDelivery/piper-doc/',
        libraryRepositoryUrl: 'https://github.wdf.sap.corp/ContinuousDelivery/piper-library/'
    ) {
        def script = checkScript(this, parameters) ?: this
        def utils = parameters.juStabUtils ?: new Utils()
        def jenkinsUtils = parameters.jenkinsUtilsStub ?: new JenkinsUtils()

        // load default & individual configuration
        Map config = ConfigurationHelper
            .loadStepDefaults(this)
            .mixinGeneralConfig(script.globalPipelineEnvironment, GENERAL_CONFIG_KEYS)
            .mixinStepConfig(script.globalPipelineEnvironment, STEP_CONFIG_KEYS)
            .mixinStageConfig(script.globalPipelineEnvironment, parameters.stageName?:env.STAGE_NAME, STEP_CONFIG_KEYS)
            .mixin(artifactUrl: script.globalPipelineEnvironment.getXMakeProperty('stage_repourl'))
            .mixin(parameters, PARAMETER_KEYS)
            .dependingOn('scanType').mixin('buildDescriptorFile')
            .dependingOn('scanType').mixin('stashContent')
            .use()

        Deprecate.configParameter(this, script.globalPipelineEnvironment, 'vulasNightlySchedule')

        // remove legacy defaults
        if (config.ppmsID && "${config.ppmsID}".startsWith('Your PPMS software component version or product version ID'))
            config.ppmsID = null
        //stays on groovy side
        switch(config.scanType) {
            case 'mta':
                def scanJobs = [:]
                scanJobs.failFast = false
                // harmonize buildDescriptorExcludeList
                config.buildDescriptorExcludeList = config.buildDescriptorExcludeList instanceof List ? config.buildDescriptorExcludeList : config.buildDescriptorExcludeList?.replaceAll(', ', ',')?.replaceAll(' ,', ',')?.tokenize(',')
                config.buildDescriptorExcludeList = normalizeFilePaths(config.buildDescriptorExcludeList)
                // create job for each pom.xml with scanType: 'maven'
                scanJobs.putAll(MtaMultiplexer.createJobs(
                    this, parameters, config.buildDescriptorExcludeList, 'Vulas', 'pom.xml', 'maven'
                ) { options -> executeVulasScan(options) })
                // create job for each setup.py with scanType: 'pip'
                scanJobs.putAll(MtaMultiplexer.createJobs(
                    this, parameters, config.buildDescriptorExcludeList, 'Vulas', 'setup.py', 'pip'
                ) { options -> executeVulasScan(options) })
                // execute Fortify scans
                parallel scanJobs
                return
            case 'pip':
                config.pip = config.pythonVersion == 'python3'?'pip3':'pip2'
                config.pythonInstallCommand = GStringTemplateEngine.newInstance().createTemplate(config.pythonInstallCommand).make([pip: config.pip]).toString()
                config.vulasRunNightly = false
                break
            case 'maven':
                config.vulasCycleCommand = GStringTemplateEngine.newInstance().createTemplate(config.vulasCycleCommand).make([vulasPlugin: config.vulasPlugin, vulasProperty: config.vulasProperty, serverUrl: config.serverUrl, backendEndpoint: config.backendEndpoint]).toString()
                config.vulasNightlyCommand = GStringTemplateEngine.newInstance().createTemplate(config.vulasNightlyCommand).make([vulasPlugin: config.vulasPlugin, vulasProperty: config.vulasProperty, serverUrl: config.serverUrl, backendEndpoint: config.backendEndpoint]).toString()
                break
            default:
                Notify.error(this, "The scan type '${config.scanType}' is not supported.")
        }

        //influx
        script.globalPipelineEnvironment.setInfluxStepData('vulas', false)
        utils.pushToSWA(this, script, [
            stepParam1: config.scanType,
            stepParam2: config.vulasRunNightly,
            stepParam3: config.ppmsID
        ])

        def vulas = parameters.vulasStub ?: new Vulas(script, utils, config)
        def svm = parameters.svmStub ?: new SoftwareVulnerabilityMonitor(script, utils, config)

        def path
        def vulasReportName
        def buildDescriptor
        def vulasProjectVersion

        //do the scan
	    try {
            config.stashContent = utils.unstashAll(config.stashContent)

            if (config.scanType == 'pip') {
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
            } else {
                buildDescriptor = utils.readMavenGAV(config.buildDescriptorFile)
                vulasProjectVersion = getProjectVersion(config, buildDescriptor)
                path = config.buildDescriptorFile.replaceAll('pom.xml', '')
                if ((jenkinsUtils.isJobStartedByTimer() || jenkinsUtils.isJobStartedByUser()) && config.vulasRunNightly) {
                    vulasReportName = "Vulas Nightly Report ${path.replaceFirst('\\./', '')}"
                } else {
                    vulasReportName = "Vulas Report ${path.replaceFirst('\\./', '')}"
                    vulasProjectVersion = "${vulasProjectVersion}-SNAPSHOT"
                }
                config.projectGroup = buildDescriptor['group']
                if (config.vulasLookupByGAVs != false && !config.vulasLookupByGAVs) config.vulasLookupByGAVs = [].plus(buildDescriptor['artifact'])
                config.vulasSpaceToken = vulas.initializeSpaceToken()
                executeMavenScan(script, config, utils, svm, jenkinsUtils, vulasProjectVersion)
            }

            publishReport(vulasReportName, path)
            jenkinsUtils.addRunSideBarLink("${config.serverUrl}/apps/#/${config.vulasSpaceToken}/${buildDescriptor.group}/${buildDescriptor.artifact}/${vulasProjectVersion}", "Vulas WebUI", "images/24x24/graph.png")
            echo "[${STEP_NAME}] Vulas detected no Open Source Software Security vulnerabilities. For details see the archived report or the web ui: https://vulas.mo.sap.corp/apps/#/${config.vulasSpaceToken}/${buildDescriptor.group}/${buildDescriptor.artifact}/${vulasProjectVersion}"
            script.globalPipelineEnvironment.setInfluxStepData('vulas', true)
        } catch (AbortException e) {
            if(fileExists("${path}target/vulas/report/vulas-report.html")) {
                publishReport(vulasReportName, path)
                jenkinsUtils.addRunSideBarLink("${config.serverUrl}/apps/#/${config.vulasSpaceToken}/${buildDescriptor.group}/${buildDescriptor.artifact}/${vulasProjectVersion}", "Vulas WebUI", "images/24x24/graph.png")
                Notify.error(this, "Vulas detected Open Source Software Security vulnerabilities, the project is not compliant. For details see the archived report or the web ui: https://vulas.mo.sap.corp/apps/#/${config.vulasSpaceToken}/${buildDescriptor.group}/${buildDescriptor.artifact}/${vulasProjectVersion}")
            }

            def error = extractStacktraceFromException(e)
            Notify.error(this, "Vulas scan failed due to a severe error. Please see the log for details: ${error}")
        }
        finally {
            reportMetricsToInflux(script, vulas, config.projectGroup, vulasProjectVersion, config.vulasLookupByGAVs)
        }
    }
}

void reportMetricsToInflux(script, vulas, projectGroup, vulasProjectVersion, vulasLookupByGAVs) {
    def triaged = 0
    def triagedCveString = ''
    def vulnerability = 0
    def vulnerabilityCveString = ''
    def testProvided = 0
    def testProvidedCveString = ''
    def reachable = 0
    def reachableCveString = ''
    def overall = 0
    def overallCveString = ''
    def metrics = [:]
    def vulnerabilities

    try {
        if (vulasLookupByGAVs) {
            def vulns = vulasLookupByGAVs.collect {
                artifact ->
                    def gav = projectGroup + ":" + artifact + ":" + vulasProjectVersion
                    vulas.lookupVulnerabilitiesByGAV(gav)
            }
            vulnerabilities = vulns.inject {
                v1, v2 ->
                    v1 + v2
            }
        } else {
            vulnerabilities = vulas.lookupVulnerabilities()
        }

        vulnerabilities.each {
            item ->
                overall++
                overallCveString += item.type + ';'
                if (item.reachable) {
                    reachable++
                    reachableCveString += item.type + ';'
                }

                metrics[item.scope] = metrics[item.scope] ? (metrics[item.scope] + 1) : 1
                metrics[item.scope + "_cve"] = metrics[item.scope + "_cve"] ? (metrics[item.scope + "_cve"] + item.type + ';') : '' + item.type + ';'

                switch (item.state) {
                    case 1:
                        testProvided++
                        testProvidedCveString += item.type + ';'
                        break
                    case 2:
                        vulnerability++
                        vulnerabilityCveString += item.type + ';'
                        break
                    case 4:
                        triaged++
                        triagedCveString += item.type + ';'
                        break
                }
        }
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'overall', overall)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'overall_cve', overallCveString)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'proved_reachable', reachable)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'proved_reachable_cve', reachableCveString)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'vulnerabilities', vulnerability)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'vulnerabilities_cve', vulnerabilityCveString)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'triaged_vulnerabilities', triaged)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'triaged_vulnerabilities_cve', triagedCveString)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'testProvided_vulnerabilities', testProvided)
        script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', 'testProvided_vulnerabilities_cve', testProvidedCveString)
        metrics.entrySet().each {
            entry ->
                script.globalPipelineEnvironment.setInfluxCustomDataMapProperty('vulas_data', entry.key, entry.value)
        }
    } catch (e) {
        Notify.warning(this, "Failed to report metrics to Influx DB, fetching Vulas data failed")
    }
}

def executePythonScan(script, config, svm, vulasProjectVersion, buildDescriptor) {
    dockerExecute(
        script: script,
        dockerImage: config.dockerImage,
        dockerWorkspace: config.dockerWorkspace,
        stashContent: config.stashContent
    ) {
        def options = [
            "vulas.shared.backend.serviceUrl = ${config.serverUrl}${config.backendEndpoint}",
            "vulas.core.backendConnection = READ_WRITE",
            "vulas.report.reportDir = target/vulas/report",
            "vulas.core.appContext.version = ${vulasProjectVersion}",
            "vulas.core.app.sourceDir = ${config.pythonSources.join(',')}",
            "vulas.core.app.appPrefixes = com.sap"
        ]
        if (config.vulasSpaceToken) options.add("vulas.core.space.token='${config.vulasSpaceToken}'")
        if (config.ppmsID) options.add("vulas.report.sap.scv = ${config.ppmsID}")

        def configFileName
        if(config.pythonCli) {
            configFileName = 'vulas-custom.properties'
            config.pythonSources.each { e -> e = 'app/' + e }
            if(config.pythonSources.size() == 0)
                config.pythonSources += 'app'
            options += [
                "vulas.core.appContext.group = ${buildDescriptor['group']}",
                "vulas.core.appContext.artifact = ${buildDescriptor['artifact']}",
                "vulas.core.app.sourceDir = ${config.pythonSources.join(',')}",
                "vulas.core.uploadEnabled = true"
            ]
            def pipInstallPath = sh script: "which ${config.pip}", returnStdout: true
            if (pipInstallPath) {
                options += ["vulas.core.bom.python.pip = ${pipInstallPath}"]
            }
        } else {
            configFileName = 'vulas-python.cfg'
            def pythonInstallPath = sh script: "which ${config.pythonVersion}", returnStdout: true
            if (pythonInstallPath) {
                options += ["vulas.core.bom.python.python = ${pythonInstallPath}"]
            }
        }

        def configFileBackup = ''
        def copyCommand = ''
        if (fileExists(configFileName)) {
            configFileBackup = "${configFileName}.original"
            copyCommand = "cp ${configFileName} ${configFileBackup}\n"
        }

        def path = config.buildDescriptorFile.replaceAll('setup.py', '')
        if(config.pythonCli) {
            def releaseUrl = sh script: "curl -Ls -o /dev/null -w %{url_effective} https://github.wdf.sap.corp/vulas/vulas/releases/latest", returnStdout: true
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
                find . -wholename '**/*' -not -type d -and -not -path '*/vulas-cli/*' -exec cp -p --parents {} ./vulas-cli/app \\;
                cd vulas-cli/app
                ${config.pythonInstallCommand}
                cd ..
                java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal clean
                java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal app
                java -jar vulas-cli-${version}-jar-with-dependencies.jar -goal report
            """
        } else {
            fetchExemptionFileFromSVM(config, svm, "${path}")

            sh """
                cd ${path}
                ${copyCommand}printf \'${options.join('\n')}\n\' ${configFileBackup} > ${configFileName}
                ${config.pythonInstallCommand}
            """

            sh "cd ${path} && ${config.pythonVersion} setup.py clean && ${config.pythonVersion} setup.py app && ${config.pythonVersion} setup.py report"
        }
    }
}

def executeMavenScan(script, config, utils, svm, jenkinsUtils, vulasProjectVersion) {
    def scanOptions= [
        '--update-snapshots'
    ]
    def command
    if ((jenkinsUtils.isJobStartedByTimer() || jenkinsUtils.isJobStartedByUser()) && config.vulasRunNightly) {
        command = config.vulasNightlyCommand
        scanOptions.add("-Dvulas.core.clean.purgeVersions=${config.vulasPurgeVersions}")
        scanOptions.add("-Dvulas.core.clean.purgeVersions.keepLast=${config.vulasPurgeVersionsKeepLast}")
    } else {
        command = config.vulasCycleCommand
    }
    def reportOptions= [
        '--fail-at-end',
        "${config.vulasProperty}", // default: -Dvulas
        '-Dvulas.report.overridePomVersion=true'
    ]
    def options = [
        "--settings ${config.mvnSettingsFile}",
        "-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn",
        '--batch-mode',
        "--file ${config.buildDescriptorFile}",
        "-Dvulas.core.appContext.version=${vulasProjectVersion}",
        "-Dvulas.shared.backend.serviceUrl=${config.serverUrl}${config.backendEndpoint}"
    ]
    if(config.vulasSpaceToken) options.add("-Dvulas.core.space.token='${config.vulasSpaceToken}'")
    if(config.ppmsID) options.add("-Dvulas.report.sap.scv='${config.ppmsID}'")

//groovy
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
}

void fetchExemptionFileFromSVM(config, svm, targetFile = './') {
    if(config.svmCredentialsId) {
        svm.fetchExemptionFile(targetFile)
    }
}

def getProjectVersion(config, buildDescriptor){
    def version = null
    // load version from version mapping
    if (null != config.vulasVersionMapping && !config.vulasVersionMapping.keySet().isEmpty())
        version = config.vulasVersionMapping[config.buildDescriptorFile.replaceFirst('\\./', '')] ?: null
    // load version from buildDescriptor file
    if (null == version)
        version = buildDescriptor.version.split('\\.')[0]
    return version
}

void publishReport(name, path){
    if(name.endsWith('/')) name = name.substring(0, name.length() - 1)
    publishHTML([allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true, reportDir: "${path}target/vulas/report", reportFiles: 'vulas-report.html', reportName: name.trim()])
    archiveArtifacts artifacts: "${path.replaceFirst('\\./', '')}target/vulas/report/vulas-report.*", allowEmptyArchive: false
}

private normalizeFilePaths(excluded){
    def result = []
    excluded.each {
        item -> result.add(new File(item).path)
    }
    return result
}

@NonCPS
def extractStacktraceFromException(e) {
    def sw = new StringWriter()
    def pw = new PrintWriter(sw)
    e.printStackTrace(pw)
    sw.toString()
}

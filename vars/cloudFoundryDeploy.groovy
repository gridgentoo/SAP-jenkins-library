import com.sap.piper.BashUtils
import com.sap.piper.CfManifestUtils
import com.sap.piper.ConfigurationHelper
import com.sap.piper.GenerateDocumentation
import com.sap.piper.JenkinsUtils
import com.sap.piper.Utils
import groovy.transform.Field
import com.sap.piper.BuildTool
import com.sap.piper.DownloadCacheUtils
import groovy.transform.Field

import static com.sap.piper.Prerequisites.checkScript

@Field String STEP_NAME = getClass().getName()
@Field String METADATA_FILE = 'metadata/cloudFoundryDeploy.yaml'

//Metadata maintained in file project://resources/metadata/cloudFoundryDeploy.yaml

@Field Set GENERAL_CONFIG_KEYS = [
    'cloudFoundry',
    /**
     * Cloud Foundry API endpoint.
     * @parentConfigKey cloudFoundry
     */
    'apiEndpoint',
    /**
     * Defines the name of the application to be deployed to the Cloud Foundry space.
     * @parentConfigKey cloudFoundry
     */
    'appName',
    /**
     * Credentials to be used for deployment.
     * @parentConfigKey cloudFoundry
     */
    'credentialsId',
    /**
     * Defines the manifest to be used for deployment to Cloud Foundry.
     * @parentConfigKey cloudFoundry
     */
    'manifest',
    /**
     * Defines the manifest variables Yaml files to be used to replace variable references in manifest. This parameter
     * is optional and will default to `["manifest-variables.yml"]`. This can be used to set variable files like it
     * is provided by `cf push --vars-file <file>`.
     *
     * If the manifest is present and so are all variable files, a variable substitution will be triggered that uses
     * the `cfManifestSubstituteVariables` step before deployment. The format of variable references follows the
     * [Cloud Foundry standard](https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#variable-substitution).
     * @parentConfigKey cloudFoundry
     */
    'manifestVariablesFiles',
    /**
     * Defines a `List` of variables as key-value `Map` objects used for variable substitution within the file given by `manifest`.
     * Defaults to an empty list, if not specified otherwise. This can be used to set variables like it is provided
     * by `cf push --var key=value`.
     *
     * The order of the maps of variables given in the list is relevant in case there are conflicting variable names and values
     * between maps contained within the list. In case of conflicts, the last specified map in the list will win.
     *
     * Though each map entry in the list can contain more than one key-value pair for variable substitution, it is recommended
     * to stick to one entry per map, and rather declare more maps within the list. The reason is that
     * if a map in the list contains more than one key-value entry, and the entries are conflicting, the
     * conflict resolution behavior is undefined (since map entries have no sequence).
     *
     * Note: variables defined via `manifestVariables` always win over conflicting variables defined via any file given
     * by `manifestVariablesFiles` - no matter what is declared before. This is the same behavior as can be
     * observed when using `cf push --var` in combination with `cf push --vars-file`.
     */
    'manifestVariables',
    /**
     * Defines additional extension descriptor file for deployment with the mtaDeployPlugin.
     */
    'mtaExtensionDescriptor',
    /**
     * Cloud Foundry target organization.
     * @parentConfigKey cloudFoundry
     */
    'org',
    /**
     * Cloud Foundry target space.
     * @parentConfigKey cloudFoundry
     */
    'space',
    /**
     * Defines the tool which should be used for deployment.
     * @possibleValues 'cf_native', 'mtaDeployPlugin'
     */
    'deployTool',
    /**
     * Defines the type of deployment, either `standard` deployment which results in a system downtime or a zero-downtime `blue-green` deployment.
     * If 'cf_native' as deployType and 'blue-green' as deployTool is used in combination, your manifest.yaml may only contain one application.
     * If this application has the option 'no-route' active the deployType will be changed to 'standard'.
     * @possibleValues 'standard', 'blue-green'
     */
    'deployType',
    /**
     * In case of a `blue-green` deployment the old instance will be deleted by default. If this option is set to true the old instance will remain stopped in the Cloud Foundry space.
     * @possibleValues true, false
     */
    'keepOldInstance',
    /** @see dockerExecute */
    'dockerImage',
    /** @see dockerExecute */
    'dockerWorkspace',
    /** @see dockerExecute */
    'stashContent',
    /**
     * Additional parameters passed to cf native deployment command.
     */
    'cfNativeDeployParameters',
    /**
     * Addition command line options for cf api command.
     * No escaping/quoting is performed. Not recommanded for productive environments.
     */
    'apiParameters',
    /**
     * Addition command line options for cf login command.
     * No escaping/quoting is performed. Not recommanded for productive environments.
     */
    'loginParameters',
    /**
     * Additional parameters passed to mta deployment command.
     */
    'mtaDeployParameters',
    /**
     * Defines additional extension descriptor file for deployment with the mtaDeployPlugin.
     */
    'mtaExtensionDescriptor',
    /**
     * Defines the path to *.mtar for deployment with the mtaDeployPlugin.
     */
    'mtaPath',
    /**
     * Allows to specify a script which performs a check during blue-green deployment. The script gets the FQDN as parameter and returns `exit code 0` in case check returned `smokeTestStatusCode`.
     * More details can be found [here](https://github.com/bluemixgaragelondon/cf-blue-green-deploy#how-to-use) <br /> Currently this option is only considered for deployTool `cf_native`.
     */
    'smokeTestScript',
    /**
     * Expected status code returned by the check.
     */
    'smokeTestStatusCode',
    /**
     * Provides more output. May reveal sensitive information.
     * @possibleValues true, false
     */
    'verbose',
    /**
     * Docker image deployments are supported (via manifest file in general)[https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#docker].
     * If no manifest is used, this parameter defines the image to be deployed. The specified name of the image is
     * passed to the `--docker-image` parameter of the cf CLI and must adhere it's naming pattern (e.g. REPO/IMAGE:TAG).
     * See (cf CLI documentation)[https://docs.cloudfoundry.org/devguide/deploy-apps/push-docker.html] for details.
     *
     * Note: The used Docker registry must be visible for the targeted Cloud Foundry instance.
     */
    'deployDockerImage',
    /**
     * If the specified image in `deployDockerImage` is contained in a Docker registry, which requires authorization
     * this defines the credentials to be used.
     */
    'dockerCredentialsId',
]
@Field Set STEP_CONFIG_KEYS = GENERAL_CONFIG_KEYS
@Field Set PARAMETER_KEYS = STEP_CONFIG_KEYS

@Field Map CONFIG_KEY_COMPATIBILITY = [cloudFoundry: [apiEndpoint: 'cfApiEndpoint', appName: 'cfAppName', credentialsId: 'cfCredentialsId', manifest: 'cfManifest', manifestVariablesFiles: 'cfManifestVariablesFiles', manifestVariables: 'cfManifestVariables', org: 'cfOrg', space: 'cfSpace']]

/**
 * Deploys an application to a test or production space within Cloud Foundry.
 * Deployment can be done
 *
 * * in a standard way
 * * in a zero downtime manner (using a [blue-green deployment approach](https://martinfowler.com/bliki/BlueGreenDeployment.html))
 *
 * !!! note "Deployment supports multiple deployment tools"
 *     Currently the following are supported:
 *
 *     * Standard `cf push` and [Bluemix blue-green plugin](https://github.com/bluemixgaragelondon/cf-blue-green-deploy#how-to-use)
 *     * [MTA CF CLI Plugin](https://github.com/cloudfoundry-incubator/multiapps-cli-plugin)
 *
 * !!! note
 * Due to [an incompatible change](https://github.com/cloudfoundry/cli/issues/1445) in the Cloud Foundry CLI, multiple buildpacks are not supported by this step.
 * If your `application` contains a list of `buildpacks` instead a single `buildpack`, this will be automatically re-written by the step when blue-green deployment is used.
 *
 * !!! note
 * Cloud Foundry supports the deployment of multiple applications using a single manifest file.
 * This option is supported with Piper.
 *
 * In this case define `appName: ''` since the app name for the individual applications have to be defined via the manifest.
 * You can find details in the [Cloud Foundry Documentation](https://docs.cloudfoundry.org/devguide/deploy-apps/manifest.html#multi-apps)
 */
@GenerateDocumentation
void call(Map parameters = [:]) {

    handlePipelineStepErrors(stepName: STEP_NAME, stepParameters: parameters) {

        def utils = parameters.juStabUtils ?: new Utils()
        def jenkinsUtils = parameters.jenkinsUtilsStub ?: new JenkinsUtils()

        final script = checkScript(this, parameters) ?: this

        Map config = ConfigurationHelper.newInstance(this)
            .loadStepDefaults()
            .mixinGeneralConfig(script.commonPipelineEnvironment, GENERAL_CONFIG_KEYS, CONFIG_KEY_COMPATIBILITY)
            .mixinStepConfig(script.commonPipelineEnvironment, STEP_CONFIG_KEYS, CONFIG_KEY_COMPATIBILITY)
            .mixinStageConfig(script.commonPipelineEnvironment, parameters.stageName ?: env.STAGE_NAME, STEP_CONFIG_KEYS, CONFIG_KEY_COMPATIBILITY)
            .mixin(parameters, PARAMETER_KEYS, CONFIG_KEY_COMPATIBILITY)
            .dependingOn('deployTool').mixin('dockerImage')
            .dependingOn('deployTool').mixin('dockerWorkspace')
            .withMandatoryProperty('cloudFoundry/org')
            .withMandatoryProperty('cloudFoundry/space')
            .withMandatoryProperty('cloudFoundry/credentialsId')
            .use()


// FIXME(fwilhe) jsut for testing
        echo "dbg>> before cf deploy"
        withCredentials([usernamePassword(
            credentialsId: config.cloudFoundry.credentialsId,
            passwordVariable: 'password',
            usernameVariable: 'username'
        )]) {
            parameters['apiEndpoint'] = config.cloudFoundry.apiEndpoint
            parameters['org'] = config.cloudFoundry.org
            parameters['password'] = password
            parameters['space'] = config.cloudFoundry.space
            parameters['username'] = username
            parameters['manifest'] = config.cloudFoundry.manifest
            piperExecuteBin(parameters, STEP_NAME, METADATA_FILE, [])
            echo "dbg>> after cf deploy"
        }
    }
}

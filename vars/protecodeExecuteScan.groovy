import com.sap.piper.JenkinsUtils
import com.sap.piper.MapUtils
import com.sap.piper.PiperGoUtils
import com.sap.piper.Utils
import groovy.transform.Field

import static com.sap.piper.Prerequisites.checkScript

@Field String STEP_NAME = getClass().getName()
@Field String METADATA_FILE = 'metadata/protecode.yaml'

/**
 * Protecode is an Open Source Vulnerability Scanner that is capable of scanning binaries. It can be used to scan docker images but is supports many other programming languages especially those of the C family. You can find more details on its capabilities in the [OS3 - Open Source Software Security JAM](https://jam4.sapjam.com/groups/XgeUs0CXItfeWyuI4k7lM3/overview_page/aoAsA0k4TbezGFyOkhsXFs). For getting access to Protecode please visit the [guide](https://go.sap.corp/protecode).
 */
void call(Map parameters = [:]) {
    def jenkinsUtils = parameters.jenkinsUtilsStub ?: new JenkinsUtils()

    List credentials = [
        [type: 'file', id: 'dockerCredentialsId', env: ['DOCKER_CONFIG']],
        [type: 'usernamePassword', id: 'protecodeCredentialsId', env: ['PIPER_username', 'PIPER_password']],
    ]
    piperExecuteBin(parameters, STEP_NAME, METADATA_FILE, credentials, false, false, true)

    // use step results
    def json = readJSON (file: "protecodescan_vulns.json")
    def report = readJSON (file: 'protecodeExecuteScan.json')

    archiveArtifacts artifacts: report['target'], allowEmptyArchive: !report['mandatory']
    archiveArtifacts artifacts: "protecodeExecuteScan.json", allowEmptyArchive: false
    archiveArtifacts artifacts: "protecodescan_vulns.json", allowEmptyArchive: false
    
    jenkinsUtils.removeJobSideBarLinks("artifact/${report['target']}")
    jenkinsUtils.addJobSideBarLink("artifact/${report['target']}", "Protecode Report", "images/24x24/graph.png")
    jenkinsUtils.addRunSideBarLink("artifact/${report['target']}", "Protecode Report", "images/24x24/graph.png")
    jenkinsUtils.addRunSideBarLink("${report['protecodeServerUrl']}/products/${report['productID']}/", "Protecode WebUI", "images/24x24/graph.png")
}

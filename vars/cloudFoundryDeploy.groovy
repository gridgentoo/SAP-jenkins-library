import com.sap.piper.BuildTool
import com.sap.piper.DownloadCacheUtils
import groovy.transform.Field

import static com.sap.piper.Prerequisites.checkScript

@Field String STEP_NAME = getClass().getName()
@Field String METADATA_FILE = 'metadata/cloudFoundryDeploy.yaml'

//Metadata maintained in file project://resources/metadata/cloudFoundryDeploy.yaml


// FIXME(fwilhe) jsut for testing
void call(Map parameters = [:]) {
    final script = checkScript(this, parameters) ?: this
    echo "dbg>> before cf deploy"
    piperExecuteBin(parameters, STEP_NAME, METADATA_FILE, null)
    echo "dbg>> after cf deploy"
}

package whoami.checkers;

import burp.api.montoya.http.message.HttpRequestResponse;
import whoami.core.CoreModules;

public class SSRFChecker implements VulnerabilityChecker {
    @Override
    public String getName() {
        return "SSRF";
    }

    @Override
    public void check(HttpRequestResponse requestResponse, CoreModules core) {
        core.logger.log(getName(), "SSRF checker not implemented yet.");
    }
}

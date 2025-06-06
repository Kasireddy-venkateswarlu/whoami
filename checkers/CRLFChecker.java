package whoami.checkers;

import burp.api.montoya.http.message.HttpRequestResponse;
import whoami.core.CoreModules;

public class CRLFChecker implements VulnerabilityChecker {
    @Override
    public String getName() {
        return "CRLF";
    }

    @Override
    public void check(HttpRequestResponse requestResponse, CoreModules core) {
        core.logger.log(getName(), "CRLF checker not implemented yet.");
    }
}

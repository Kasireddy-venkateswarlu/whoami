package whoami.checkers;

import burp.api.montoya.http.message.HttpRequestResponse;
import whoami.core.CoreModules;

public class XSSChecker implements VulnerabilityChecker {
    @Override
    public String getName() {
        return "XSS";
    }

    @Override
    public void check(HttpRequestResponse requestResponse, CoreModules core) {
        core.logger.log(getName(), "XSS checker not implemented yet.");
    }
}

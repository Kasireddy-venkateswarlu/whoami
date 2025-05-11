package whoami.checkers;

import burp.api.montoya.http.message.requests.HttpRequest;
import whoami.core.CoreModules;

public class CMDInjectionChecker {
    private final CoreModules core;

    public CMDInjectionChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForCMDInjection(HttpRequest request) {
        core.logger.log("CMDInjection", "Command Injection checker not implemented yet.");
    }

    private String getName() {
        return "CMDInjection";
    }
}

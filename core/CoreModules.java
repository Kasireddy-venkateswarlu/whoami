// core/CoreModules.java
package whoami.core;

import burp.api.montoya.MontoyaApi;
import whoami.ui.UIManager;

public class CoreModules {
    public final Logger logger;
    public final HttpRequestSender requestSender;
    public final UIManager uiManager;
    public final ScopeFilter scopeFilter;
    private final MontoyaApi api;

    public CoreModules(MontoyaApi api, UIManager uiManager) {
        this.api = api;
        this.logger = new Logger(api.logging());
        this.requestSender = new HttpRequestSender(api, logger, uiManager);
        this.uiManager = uiManager;
        this.scopeFilter = new ScopeFilter(api, uiManager.getConfig(), logger);
    }

    public MontoyaApi getApi() {
        return api;
    }
}

// core/ScopeFilter.java
package whoami.core;

import burp.api.montoya.MontoyaApi;
import whoami.ui.UIManager.Config;

public class ScopeFilter {
    private final MontoyaApi api;
    private final Config config;
    private final Logger logger;

    public ScopeFilter(MontoyaApi api, Config config, Logger logger) {
        this.api = api;
        this.config = config;
        this.logger = logger;
    }

    public boolean isInScope(String url) {
        boolean inScope = api.scope().isInScope(url);
        logger.log("SCOPE", "Checking scope for URL: " + url + ", In Scope: " + inScope);
        return inScope;
    }
}

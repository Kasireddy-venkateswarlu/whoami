package whoami.core;

import burp.api.montoya.MontoyaApi;
import whoami.ui.UIManager;

public class ScopeFilter {
    private final MontoyaApi api;
    private final UIManager.Config config; // Use UIManager.Config
    private final Logger logger;

    public ScopeFilter(MontoyaApi api, UIManager.Config config, Logger logger) {
        this.api = api;
        this.config = config;
        this.logger = logger;
    }

    public boolean isInScope(String url) {
        return api.scope().isInScope(url);
    }
}

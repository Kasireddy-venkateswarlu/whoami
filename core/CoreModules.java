package whoami.core;

import burp.api.montoya.MontoyaApi;
import whoami.ui.UIManager;

public class CoreModules {
    public final Logger logger;
    public final HttpRequestSender requestSender;
    public final UIManager uiManager;
    public final ScopeFilter scopeFilter;
    public final ScanDatabaseHelper dbHelper; // Added for duplicate scan prevention
    private final MontoyaApi api;

    public CoreModules(MontoyaApi api, UIManager uiManager) {
        this.api = api;
        this.logger = new Logger(api.logging());
        this.dbHelper = new ScanDatabaseHelper(logger); // Initialize database helper
        this.requestSender = new HttpRequestSender(api, logger, uiManager);
        this.uiManager = uiManager;
        this.scopeFilter = new ScopeFilter(api, uiManager.getConfig(), logger);
    }

    public MontoyaApi getApi() {
        return api;
    }
}

package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.sitemap.SiteMap;
import whoami.ui.UIManager;

public class CoreModules {
    public final HttpRequestSender requestSender;
    public final ScopeFilter scopeFilter;
    public final ParameterHandler parameterHandler;
    public final ResponseAnalyzer responseAnalyzer;
    public final Logger logger;
    public final UIManager uiManager;
    public final SiteMap siteMap;

    public CoreModules(MontoyaApi api, UIManager uiManager) {
        this.logger = new Logger(api);
        this.uiManager = uiManager;
        this.requestSender = new HttpRequestSender(api, logger, uiManager); // Pass UIManager
        this.scopeFilter = new ScopeFilter(api, uiManager.getConfig(), logger);
        this.parameterHandler = new ParameterHandler(logger);
        this.responseAnalyzer = new ResponseAnalyzer(api, logger);
        this.siteMap = api.siteMap();
    }

    public SiteMap siteMap() {
        return siteMap;
    }
}

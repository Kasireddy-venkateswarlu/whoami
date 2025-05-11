// WhoamiExtension.java
package whoami;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import whoami.checkers.SQLiChecker;
import whoami.checkers.XSSChecker;
import whoami.core.CoreModules;
import whoami.core.ExtensionUtils;
import whoami.ui.UIManager;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class WhoamiExtension implements BurpExtension {
    private CoreModules core;
    private SQLiChecker sqliChecker;
    private XSSChecker xssChecker;
    private ExecutorService executorService;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("whoami");

        // Initialize ExecutorService for async tasks
        executorService = Executors.newFixedThreadPool(5);

        UIManager uiManager = new UIManager(api);
        uiManager.createTab();
        core = new CoreModules(api, uiManager);
        sqliChecker = new SQLiChecker(core);
        xssChecker = new XSSChecker(core);

        // Register context menu provider
        api.userInterface().registerContextMenuItemsProvider(new ExtensionUtils(api, core.logger, sqliChecker, xssChecker));
        core.logger.logToOutput("Registered context menu provider for SQLi and XSS testing");

        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }

            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                if (!core.uiManager.getConfig().isEnabled()) {
                    core.logger.logToOutput("Extension is disabled, allowing request: " + interceptedRequest.url().toString());
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }

                String url = interceptedRequest.url().toString();
                String method = interceptedRequest.method();

                // Check excluded extensions
                if (hasExcludedExtension(url, core.uiManager.getConfig().getExcludedExtensions())) {
                    core.logger.logToOutput("Skipping tests for URL with excluded extension: " + url);
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }

                if (!core.scopeFilter.isInScope(url)) {
                    core.logger.logToOutput("Dropped OUT-OF-SCOPE request: " + url);
                    return ProxyRequestToBeSentAction.drop();
                }

                if (!core.uiManager.getConfig().isMethodAllowed(method)) {
                    core.logger.logToOutput("Dropped request with disallowed method [" + method + "]: " + url);
                    return ProxyRequestToBeSentAction.drop();
                }

                core.logger.logToOutput("Allowed " + method + " request in scope: " + url);

                // Process SQL injection asynchronously
                if (core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false)) {
                    executorService.submit(() -> sqliChecker.checkForSQLi(interceptedRequest));
                }

                // Process XSS asynchronously
                if (core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false)) {
                    executorService.submit(() -> xssChecker.checkForXSS(interceptedRequest));
                }

                // Send original request immediately
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }
        });

        core.logger.logToOutput("whoami extension loaded with method filtering, SQL injection testing, XSS testing, JSON handling, and context menu.");
    }

    private boolean hasExcludedExtension(String url, Set<String> excludedExtensions) {
        if (excludedExtensions.isEmpty()) {
            return false;
        }
        String lowerUrl = url.toLowerCase();
        for (String ext : excludedExtensions) {
            if (lowerUrl.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }
}

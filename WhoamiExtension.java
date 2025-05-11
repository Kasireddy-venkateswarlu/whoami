package whoami;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import whoami.checkers.SQLiChecker;
import whoami.core.CoreModules;
import whoami.ui.UIManager;

public class WhoamiExtension implements BurpExtension {
    private CoreModules core;
    private SQLiChecker sqliChecker;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("whoami");

        UIManager uiManager = new UIManager(api);
        uiManager.createTab(); // Let UIManager handle tab registration
        core = new CoreModules(api, uiManager);
        sqliChecker = new SQLiChecker(core);

        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                if (!core.uiManager.getConfig().isEnabled()) {
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }

                String url = interceptedRequest.url().toString();
                String method = interceptedRequest.method();

                if (!core.scopeFilter.isInScope(url)) {
                    core.logger.logToOutput("Dropped OUT-OF-SCOPE request: " + url);
                    return ProxyRequestToBeSentAction.drop();
                }

                if (!core.uiManager.getConfig().isMethodAllowed(method)) {
                    core.logger.logToOutput("Dropped request with disallowed method [" + method + "]: " + url);
                    return ProxyRequestToBeSentAction.drop();
                }

                core.logger.logToOutput("Allowed " + method + " request in scope: " + url);

                if (core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false)) {
                    sqliChecker.checkForSQLi(interceptedRequest);
                }

                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }

            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }
        });

<<<<<<< HEAD
        core.logger.logToOutput("whoami extension loaded with method filtering and SQL injectionnullhat testing.");
=======
        core.logger.logToOutput("whoami extension loaded with method filtering and SQL injection testingkasireddy.");
>>>>>>> 9a3674a721e2ffc0c3f6cad3b859616ba985e873
    }
}

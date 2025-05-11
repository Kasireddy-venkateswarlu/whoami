package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import whoami.ui.UIManager;

public class HttpRequestSender {
    private final MontoyaApi api;
    private final Logger logger;
    private final UIManager uiManager;

    public HttpRequestSender(MontoyaApi api, Logger logger, UIManager uiManager) {
        this.api = api;
        this.logger = logger;
        this.uiManager = uiManager;
    }

    public HttpRequestResponse sendRequest(HttpRequest request, String sessionId, boolean followRedirects) {
        return sendRequest(request, sessionId, followRedirects, false); // Default: respect delay
    }

    public HttpRequestResponse sendRequest(HttpRequest request, String sessionId, boolean followRedirects, boolean bypassDelay) {
        logger.log("REQUEST", "Sending request to: " + request.url().toString());
        long delayMillis = bypassDelay ? 0 : uiManager.getConfig().getDelayMillis(); // Bypass delay if requested
        if (delayMillis > 0) {
            logger.log("DELAY", "Applying delay of " + delayMillis + " ms for request to: " + request.url());
            try {
                Thread.sleep(delayMillis);
                logger.log("DELAY", "Completed delay of " + delayMillis + " ms");
            } catch (InterruptedException e) {
                logger.logError("DELAY", "Delay interrupted for request to: " + request.url() + ", error: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
        } else {
            logger.log("DELAY", "No delay applied (delayMillis = 0 or bypassed) for request to: " + request.url());
        }
        return api.http().sendRequest(request);
    }

    public HttpRequestResponse sendRequest(HttpRequest request) {
        return sendRequest(request, "", false);
    }
}

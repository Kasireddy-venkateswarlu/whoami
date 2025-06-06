// core/HttpRequestSender.java
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

    public HttpRequestResponse sendRequest(HttpRequest request, String prefix, boolean logRequest, boolean bypassDelay) {
        if (!bypassDelay && uiManager.getConfig().getDelayMillis() > 0) {
            try {
                logger.log("DELAY", "Applying delay of " + uiManager.getConfig().getDelayMillis() + "ms");
                Thread.sleep(uiManager.getConfig().getDelayMillis());
            } catch (InterruptedException e) {
                logger.logError("DELAY", "Interrupted during delay: " + e.getMessage());
            }
        } else {
            logger.log("DELAY", "No delay applied (delayMillis = " + uiManager.getConfig().getDelayMillis() + " or bypassed)");
        }

        if (logRequest) {
            logger.log("REQUEST", prefix + "Sending request: " + request.url());
        }

        HttpRequestResponse response = api.http().sendRequest(request);
        if (logRequest) {
            logger.log("REQUEST", prefix + "Response received for: " + request.url() + ", Status: " +
                    (response.response() != null ? response.response().statusCode() : "No response"));
        }

        return response;
    }
}

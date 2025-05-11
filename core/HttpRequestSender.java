package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public class HttpRequestSender {
    private final MontoyaApi api;
    private final Logger logger;
    private final long delayMillis;

    public HttpRequestSender(MontoyaApi api, Logger logger, long delayMillis) {
        this.api = api;
        this.logger = logger;
        this.delayMillis = delayMillis;
    }

    public HttpRequestResponse sendRequest(HttpRequest request, String sessionId, boolean followRedirects) {
        logger.log("REQUEST", "Sending request to: " + request.url().toString());
        if (delayMillis > 0) {
            logger.log("DELAY", "Applying delay of " + delayMillis + " ms");
            try {
                Thread.sleep(delayMillis);
                logger.log("DELAY", "Completed delay of " + delayMillis + " ms");
            } catch (InterruptedException e) {
                logger.logError("DELAY", "Delay interrupted: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
        }
        return api.http().sendRequest(request);
    }

    public HttpRequestResponse sendRequest(HttpRequest request) {
        return sendRequest(request, "", false);
    }
}

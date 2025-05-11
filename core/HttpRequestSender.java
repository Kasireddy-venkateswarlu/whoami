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
        // Simulate delay if configured
        if (delayMillis > 0) {
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                logger.logToOutput("Request interrupted: " + e.getMessage());
            }
        }
        // Ignore sessionId for simplicity; extend if needed
        return api.http().sendRequest(request);
    }

    // Overload for simpler usage in SQLiChecker
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return sendRequest(request, "", false);
    }
}

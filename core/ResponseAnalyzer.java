package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;

public class ResponseAnalyzer {
    private final MontoyaApi api;
    private final Logger logger;

    public ResponseAnalyzer(MontoyaApi api, Logger logger) {
        this.api = api;
        this.logger = logger;
    }

    public int getStatusCode(HttpResponse response, String context, String identifier) {
        if (response == null) {
            logger.logError(context, "No response received for: " + identifier);
            return -1;
        }
        int statusCode = response.statusCode();
        logger.log(context, "Response status code for " + identifier + ": " + statusCode);
        return statusCode;
    }
}

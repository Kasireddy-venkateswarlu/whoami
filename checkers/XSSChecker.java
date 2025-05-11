// checkers/XSSChecker.java
package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import whoami.core.CoreModules;

public class XSSChecker {
    private final CoreModules core;
    private static final String XSS_PAYLOAD = "<h1>hai</h1>";

    public XSSChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForXSS(HttpRequest request) {
        checkForXSS(request, false); // Default: respect delay
    }

    private void checkForXSS(HttpRequest request, boolean bypassDelay) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("XSS", "Starting XSS testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay);

        boolean hasParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("XSS", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("XSS", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasParameters = true;

            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            // Try unencoded payload
            HttpParameter paramWithPayload = HttpParameter.parameter(name, value + XSS_PAYLOAD, type);
            HttpRequest req = request.withUpdatedParameters(paramWithPayload);
            core.logger.log("XSS", "Sending unencoded payload for parameter: " + name);
            HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
            int statusCode = resp.response() != null ? resp.response().statusCode() : -1;

            // If 400, retry with encoded payload
            if (statusCode == 400) {
                String encodedPayload = core.getApi().utilities().urlUtils().encode(XSS_PAYLOAD);
                paramWithPayload = HttpParameter.parameter(name, value + encodedPayload, type);
                req = request.withUpdatedParameters(paramWithPayload);
                core.logger.log("XSS", "Retrying with encoded payload for parameter: " + name);
                resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
            }

            // Check if response is not JSON and contains the unencoded payload
            String contentType = resp.response() != null ? resp.response().headerValue("Content-Type") : null;
            if (contentType != null && contentType.contains("application/json")) {
                core.logger.log("XSS", "Skipping JSON response for parameter: " + name);
                continue;
            }

            String responseBody = resp.response() != null ? resp.response().bodyToString() : "";
            if (responseBody.contains(XSS_PAYLOAD)) {
                core.logger.log("XSS", "[VULNERABLE] XSS found for parameter: " + name + " with payload: " + XSS_PAYLOAD);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("XSS found in parameter: " + name + "\n" +
                                   "Payload: " + XSS_PAYLOAD + "\n" +
                                   "Unencoded payload reflected in response body, indicating potential XSS vulnerability.");
                core.getApi().siteMap().add(resp.withAnnotations(annotations));
            }
        }

        if (!hasParameters) {
            core.logger.log("XSS", "No testable parameters found");
        }

        core.logger.log("XSS", "Completed XSS testing for URL: " + url);
    }

    public void runContextMenuXssTest(HttpRequestResponse requestResponse) {
        core.logger.log("CONTEXT", "=== Starting XSS Test from context menu ===");
        try {
            if (requestResponse == null || requestResponse.request() == null) {
                core.logger.logError("CONTEXT", "RequestResponse or Request is null");
                return;
            }

            HttpRequest request = requestResponse.request();
            String url = request.url();
            String method = request.method();

            core.logger.log("CONTEXT", "URL: " + url + ", Method: " + method);
            core.logger.log("CONTEXT", "Parameters: " + request.parameters().size());
            core.logger.log("CONTEXT", "Bypassing all filters: Enabled=" + core.uiManager.getConfig().isEnabled() +
                    ", XSS Toggle=" + core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false) +
                    ", Cookie Testing=" + core.uiManager.getConfig().isTestCookies() +
                    ", Excluded Extensions=" + core.uiManager.getConfig().getExcludedExtensions() +
                    ", Method Allowed=" + core.uiManager.getConfig().isMethodAllowed(method) +
                    ", Delay=" + core.uiManager.getConfig().getDelayMillis() + "ms");

            // Temporarily override settings for context menu test
            boolean originalCookieTesting = core.uiManager.getConfig().isTestCookies();
            core.uiManager.getConfig().setTestCookies(true); // Always test cookies
            boolean originalXssToggle = core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false);
            core.uiManager.getConfig().getCheckers().put("XSS", true); // Force XSS testing

            // Run XSS test with delay bypassed
            checkForXSS(request, true); // Bypass delay

            // Restore original settings
            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("XSS", originalXssToggle);

            core.logger.log("CONTEXT", "=== Completed XSS Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu XSS test: " + e.getMessage());
        }
    }
}

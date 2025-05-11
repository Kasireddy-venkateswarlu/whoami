package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;
import whoami.core.CoreModules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        // Handle standard parameters
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("XSS", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("XSS", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

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

        if (!hasStandardParameters) {
            core.logger.log("XSS", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("XSS", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("XSS", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, request, bypassDelay);
                    } catch (JSONException e) {
                        core.logger.logError("XSS", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("XSS", "Non-JSON Content-Type, skipping JSON testing");
            }
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

    private void processJsonNode(Object node, String path, String url, HttpRequest originalRequest, boolean bypassDelay) {
        core.logger.log("JSON", "Processing node at path: " + (path.isEmpty() ? "<root>" : path));
        if (node instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) node;
            for (String key : jsonObject.keySet()) {
                String newPath = path.isEmpty() ? key : path + "." + key;
                processJsonNode(jsonObject.get(key), newPath, url, originalRequest, bypassDelay);
            }
        } else if (node instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) node;
            if (jsonArray.length() == 0) {
                core.logger.log("JSON", "Found empty array at: " + path + ", testing index [0]");
                testJsonPath(path + "[0]", url, originalRequest, bypassDelay);
            } else {
                for (int i = 0; i < jsonArray.length(); i++) {
                    String newPath = path + "[" + i + "]";
                    processJsonNode(jsonArray.get(i), newPath, url, originalRequest, bypassDelay);
                }
            }
        } else {
            String stringValue = node == null ? "null" : node.toString();
            testJsonPath(path, url, originalRequest, bypassDelay, stringValue);
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, boolean bypassDelay, String... stringValue) {
        String value = stringValue.length > 0 ? stringValue[0] : "";
        JSONObject modifiedJson = new JSONObject(originalRequest.bodyToString());
        if (setJsonValue(modifiedJson, path, value + XSS_PAYLOAD)) {
            HttpRequest req = originalRequest.withBody(modifiedJson.toString());
            core.logger.log("JSON", "Sending unencoded XSS payload for: " + path);
            HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
            int statusCode = resp.response() != null ? resp.response().statusCode() : -1;

            // If 400, retry with encoded payload
            if (statusCode == 400) {
                String encodedPayload = core.getApi().utilities().urlUtils().encode(XSS_PAYLOAD);
                modifiedJson = new JSONObject(originalRequest.bodyToString());
                if (setJsonValue(modifiedJson, path, value + encodedPayload)) {
                    req = originalRequest.withBody(modifiedJson.toString());
                    core.logger.log("JSON", "Retrying with encoded XSS payload for: " + path);
                    resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
                }
            }

            // Check if response is not JSON and contains the unencoded payload
            String contentType = resp.response() != null ? resp.response().headerValue("Content-Type") : null;
            if (contentType != null && contentType.contains("application/json")) {
                core.logger.log("JSON", "Skipping JSON response for: " + path);
                return;
            }

            String responseBody = resp.response() != null ? resp.response().bodyToString() : "";
            if (responseBody.contains(XSS_PAYLOAD)) {
                core.logger.log("JSON", "[VULNERABLE] XSS found for: " + path + " with payload: " + XSS_PAYLOAD);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("XSS found in JSON parameter: " + path + "\n" +
                                   "Payload: " + XSS_PAYLOAD + "\n" +
                                   "Unencoded payload reflected in response body, indicating potential XSS vulnerability.");
                core.getApi().siteMap().add(resp.withAnnotations(annotations));
            }
        }
    }

    private boolean setJsonValue(JSONObject jsonObject, String path, String value) {
        core.logger.log("JSON", "Setting value at: " + path + " to: " + value);
        try {
            List<String> parts = new ArrayList<>();
            Matcher matcher = Pattern.compile("\\w+|\\d+").matcher(path.replaceAll("\\.", " ").replaceAll("\\[", " ").replaceAll("\\]", ""));
            while (matcher.find()) {
                parts.add(matcher.group());
            }

            Object current = jsonObject;
            for (int i = 0; i < parts.size() - 1; i++) {
                String part = parts.get(i);
                if (current instanceof JSONObject) {
                    JSONObject currentObj = (JSONObject) current;
                    if (!currentObj.has(part)) {
                        currentObj.put(part, new JSONObject());
                    }
                    current = currentObj.get(part);
                } else if (current instanceof JSONArray) {
                    int index = Integer.parseInt(part);
                    JSONArray currentArray = (JSONArray) current;
                    while (currentArray.length() <= index) {
                        currentArray.put((Object) null);
                    }
                    current = currentArray.get(index);
                } else {
                    core.logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getClass().getSimpleName());
                    return false;
                }
            }

            String lastPart = parts.get(parts.size() - 1);
            if (current instanceof JSONObject) {
                ((JSONObject) current).put(lastPart, value);
            } else if (current instanceof JSONArray) {
                int index = Integer.parseInt(lastPart);
                JSONArray currentArray = (JSONArray) current;
                while (currentArray.length() <= index) {
                    currentArray.put((Object) null);
                }
                currentArray.put(index, value);
            } else {
                core.logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getClass().getSimpleName());
                return false;
            }
            return true;
        } catch (Exception e) {
            core.logger.logError("JSON", "Failed to set value at: " + path + ", error: " + e.getMessage());
            return false;
        }
    }
}

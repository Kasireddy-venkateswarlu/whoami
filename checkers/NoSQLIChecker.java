package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;
import whoami.core.CoreModules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NoSQLIChecker {
    private final CoreModules core;

    public NoSQLIChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForNoSQLI(InterceptedRequest interceptedRequest) {
        checkForNoSQLI(interceptedRequest, false); // Default: respect delay
    }

    private void checkForNoSQLI(InterceptedRequest interceptedRequest, boolean bypassDelay) {
        String url = interceptedRequest.url().toString();
        String method = interceptedRequest.method();
        core.logger.log("NoSQLI", "Starting NoSQL Injection testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay);

        // Step 1: Send base request once per unique request
        core.logger.log("NoSQLI", "Sending base request for URL: " + url);
        HttpRequestResponse baseResp = core.requestSender.sendRequest(interceptedRequest, "", false, bypassDelay);
        int baseStatus = baseResp.response() != null ? baseResp.response().statusCode() : 0;
        int baseLength = baseResp.response() != null ? baseResp.response().bodyToString().length() : 0;

        // Check for 500 Internal Server Error on base request
        if (baseResp.response() != null && baseResp.response().statusCode() == 500) {
            core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for base request");
            Annotations annotations = Annotations.annotations()
                    .withHighlightColor(HighlightColor.ORANGE)
                    .withNotes("500 Internal Server Error detected in base request for URL: " + url + "\n" +
                               "This may indicate a potential issue but is not a confirmed vulnerability.");
            core.getApi().siteMap().add(baseResp.withAnnotations(annotations));
            return;
        }

        // Handle standard parameters (including GET parameters with [$eq], [$ne])
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : interceptedRequest.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("NoSQLI", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("NoSQLI", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            // Step 2: Test with $eq injection
            String eqPayload = formatPayload(value, "$eq");
            String encodedEqPayload = core.getApi().utilities().urlUtils().encode(eqPayload);
            HttpParameter eqParam = HttpParameter.parameter(name, encodedEqPayload, type);
            HttpRequest eqReq = interceptedRequest.withUpdatedParameters(eqParam);
            core.logger.log("NoSQLI", "Sending $eq payload for parameter: " + name + ", Payload: " + eqPayload + ", Encoded Payload: " + encodedEqPayload + ", Full URL: " + eqReq.url());
            HttpRequestResponse eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
            int eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
            int eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;

            // Log response details
            core.logger.log("NoSQLI", "Response for $eq payload on " + name + ": Status=" + eqStatus + ", Length=" + eqLength);

            // Handle 400 Bad Request by retrying with stringified payload
            if (eqResp.response() != null && eqResp.response().statusCode() == 400) {
                String stringifiedEqPayload = eqPayload.replace("\"", "\\\"");
                String encodedStringifiedEqPayload = core.getApi().utilities().urlUtils().encode(stringifiedEqPayload);
                eqParam = HttpParameter.parameter(name, encodedStringifiedEqPayload, type);
                eqReq = interceptedRequest.withUpdatedParameters(eqParam);
                core.logger.log("NoSQLI", "Received 400 Bad Request, retrying with stringified $eq payload: " + stringifiedEqPayload + ", Full URL: " + eqReq.url());
                eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
                eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
                eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;
                core.logger.log("NoSQLI", "Response after stringified $eq payload on " + name + ": Status=" + eqStatus + ", Length=" + eqLength);
            }

            // Check for 500 Internal Server Error on $eq request
            if (eqResp.response() != null && eqResp.response().statusCode() == 500) {
                core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with $eq payload: " + eqPayload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.ORANGE)
                        .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                   "Payload: " + eqPayload + "\n" +
                                   "Encoded Payload: " + encodedEqPayload + "\n" +
                                   "This may indicate a potential issue but is not a confirmed vulnerability.");
                core.getApi().siteMap().add(eqResp.withAnnotations(annotations));
                continue;
            }

            // Step 3: Test with $ne injection
            String nePayload = formatPayload(value, "$ne");
            String encodedNePayload = core.getApi().utilities().urlUtils().encode(nePayload);
            HttpParameter neParam = HttpParameter.parameter(name, encodedNePayload, type);
            HttpRequest neReq = interceptedRequest.withUpdatedParameters(neParam);
            core.logger.log("NoSQLI", "Sending $ne payload for parameter: " + name + ", Payload: " + nePayload + ", Encoded Payload: " + encodedNePayload + ", Full URL: " + neReq.url());
            HttpRequestResponse neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
            int neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
            int neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;

            // Log response details
            core.logger.log("NoSQLI", "Response for $ne payload on " + name + ": Status=" + neStatus + ", Length=" + neLength);

            // Handle 400 Bad Request by retrying with stringified payload
            if (neResp.response() != null && neResp.response().statusCode() == 400) {
                String stringifiedNePayload = nePayload.replace("\"", "\\\"");
                String encodedStringifiedNePayload = core.getApi().utilities().urlUtils().encode(stringifiedNePayload);
                neParam = HttpParameter.parameter(name, encodedStringifiedNePayload, type);
                neReq = interceptedRequest.withUpdatedParameters(neParam);
                core.logger.log("NoSQLI", "Received 400 Bad Request, retrying with stringified $ne payload: " + stringifiedNePayload + ", Full URL: " + neReq.url());
                neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
                neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
                neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;
                core.logger.log("NoSQLI", "Response after stringified $ne payload on " + name + ": Status=" + neStatus + ", Length=" + neLength);
            }

            // Check for 500 Internal Server Error on $ne request
            if (neResp.response() != null && neResp.response().statusCode() == 500) {
                core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with $ne payload: " + nePayload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.ORANGE)
                        .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                   "Payload: " + nePayload + "\n" +
                                   "Encoded Payload: " + encodedNePayload + "\n" +
                                   "This may indicate a potential issue but is not a confirmed vulnerability.");
                core.getApi().siteMap().add(neResp.withAnnotations(annotations));
                continue;
            }

            // Step 4: Compare status codes
            if (baseStatus != eqStatus || eqStatus != neStatus || baseStatus == 0) {
                core.logger.log("NoSQLI", "Status codes differ or are zero for parameter: " + name + " (Base=" + baseStatus + ", $eq=" + eqStatus + ", $ne=" + neStatus + "). Skipping parameter.");
                continue;
            }

            // Step 5: Compare base and $eq response lengths
            boolean isVulnerable = false;
            if (baseLength == eqLength) {
                // Step 6: Compare $ne response length with $eq
                if (neLength != eqLength) {
                    isVulnerable = true;
                    core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected for parameter: " + name + ", $ne payload: " + nePayload);
                }
            } else {
                // Step 7: Fallback check
                if (neLength != eqLength) {
                    isVulnerable = true;
                    core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected (fallback) for parameter: " + name + ", $ne payload: " + nePayload);
                }
            }

            if (isVulnerable) {
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("NoSQL Injection detected in parameter: " + name + "\n" +
                                   "Base Value: " + value + "\n" +
                                   "$eq Payload: " + eqPayload + "\n" +
                                   "$ne Payload: " + nePayload + "\n" +
                                   "Base Status: " + baseStatus + ", Length: " + baseLength + "\n" +
                                   "$eq Status: " + eqStatus + ", Length: " + eqLength + "\n" +
                                   "$ne Status: " + neStatus + ", Length: " + neLength);
                core.getApi().siteMap().add(neResp.withAnnotations(annotations));
            } else {
                core.logger.log("NoSQLI", "No vulnerability detected for parameter: " + name);
            }

            // Additional test for GET parameters: Inject [$eq] and [$ne] (e.g., lng[$eq]=en)
            if (type == HttpParameterType.URL) {
                // Remove the original parameter to avoid conflicts
                HttpRequest baseWithoutParam = interceptedRequest.withRemovedParameters(parameter);

                // Test param[$eq]=value (send raw value, e.g., lng[$eq]=en)
                String eqArrayParamName = name + "[$eq]";
                String eqArrayValue = value; // Use the raw value, no JSON formatting
                HttpParameter eqArrayParam = HttpParameter.urlParameter(eqArrayParamName, eqArrayValue);
                HttpRequest eqArrayReq = baseWithoutParam.withAddedParameters(eqArrayParam);
                core.logger.log("NoSQLI", "Sending GET parameter $eq payload: " + eqArrayParamName + "=" + eqArrayValue + ", Full URL: " + eqArrayReq.url());
                HttpRequestResponse eqArrayResp = core.requestSender.sendRequest(eqArrayReq, "", false, bypassDelay);
                int eqArrayStatus = eqArrayResp.response() != null ? eqArrayResp.response().statusCode() : 0;
                int eqArrayLength = eqArrayResp.response() != null ? eqArrayResp.response().bodyToString().length() : 0;

                // Log response details
                core.logger.log("NoSQLI", "Response for GET $eq payload on " + name + ": Status=" + eqArrayStatus + ", Length=" + eqArrayLength);

                // Do not retry with stringified payload for raw GET parameters
                if (eqArrayResp.response() != null && eqArrayResp.response().statusCode() == 500) {
                    core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for GET parameter: " + eqArrayParamName + " with value: " + eqArrayValue);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in GET parameter: " + eqArrayParamName + "\n" +
                                       "Value: " + eqArrayValue + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(eqArrayResp.withAnnotations(annotations));
                    continue;
                }

                // Test param[$ne]=value (send raw value, e.g., lng[$ne]=en)
                String neArrayParamName = name + "[$ne]";
                String neArrayValue = value; // Use the raw value, no JSON formatting
                HttpParameter neArrayParam = HttpParameter.urlParameter(neArrayParamName, neArrayValue);
                HttpRequest neArrayReq = baseWithoutParam.withAddedParameters(neArrayParam);
                core.logger.log("NoSQLI", "Sending GET parameter $ne payload: " + neArrayParamName + "=" + neArrayValue + ", Full URL: " + neArrayReq.url());
                HttpRequestResponse neArrayResp = core.requestSender.sendRequest(neArrayReq, "", false, bypassDelay);
                int neArrayStatus = neArrayResp.response() != null ? neArrayResp.response().statusCode() : 0;
                int neArrayLength = neArrayResp.response() != null ? neArrayResp.response().bodyToString().length() : 0;

                // Log response details
                core.logger.log("NoSQLI", "Response for GET $ne payload on " + name + ": Status=" + neArrayStatus + ", Length=" + neArrayLength);

                // Do not retry with stringified payload for raw GET parameters
                if (neArrayResp.response() != null && neArrayResp.response().statusCode() == 500) {
                    core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for GET parameter: " + neArrayParamName + " with value: " + neArrayValue);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in GET parameter: " + neArrayParamName + "\n" +
                                       "Value: " + neArrayValue + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(neArrayResp.withAnnotations(annotations));
                    continue;
                }

                // Step 4: Compare status codes for GET parameters
                // Relaxed condition: Allow detection to proceed even if status codes differ slightly
                if (baseStatus == 0) {
                    core.logger.log("NoSQLI", "Base status code is zero for GET parameter: " + name + ". Skipping parameter.");
                    continue;
                }

                // Step 5: Compare base and $eq response lengths for GET parameters
                isVulnerable = false;
                if (baseLength == eqArrayLength) {
                    // Step 6: Compare $ne response length with $eq
                    if (neArrayLength != eqArrayLength) {
                        isVulnerable = true;
                        core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected for GET parameter: " + name + ", $ne payload: " + neArrayParamName + "=" + neArrayValue);
                    }
                } else {
                    // Step 7: Fallback check
                    if (neArrayLength != eqArrayLength) {
                        isVulnerable = true;
                        core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected (fallback) for GET parameter: " + name + ", $ne payload: " + neArrayParamName + "=" + neArrayValue);
                    }
                }

                if (isVulnerable) {
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.RED)
                            .withNotes("NoSQL Injection detected in GET parameter: " + name + "\n" +
                                       "Base Value: " + value + "\n" +
                                       "$eq Payload: " + eqArrayParamName + "=" + eqArrayValue + "\n" +
                                       "$ne Payload: " + neArrayParamName + "=" + neArrayValue + "\n" +
                                       "Base Status: " + baseStatus + ", Length: " + baseLength + "\n" +
                                       "$eq Status: " + eqArrayStatus + ", Length: " + eqArrayLength + "\n" +
                                       "$ne Status: " + neArrayStatus + ", Length: " + neArrayLength);
                    core.getApi().siteMap().add(neArrayResp.withAnnotations(annotations));
                } else {
                    core.logger.log("NoSQLI", "No vulnerability detected for GET parameter: " + name);
                }
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("NoSQLI", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = interceptedRequest.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("NoSQLI", "Detected JSON request");
                String body = interceptedRequest.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("NoSQLI", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, interceptedRequest, baseResp, bypassDelay);
                    } catch (JSONException e) {
                        core.logger.logError("NoSQLI", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("NoSQLI", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("NoSQLI", "Completed NoSQL Injection testing for URL: " + url);
    }

    // Overload for HttpRequest (used by context menu)
    private void checkForNoSQLI(HttpRequest request, boolean bypassDelay) {
        String url = request.url();
        String method = request.method();
        core.logger.log("NoSQLI", "Starting NoSQL Injection testing for URL: " + url + ", Method: " + method + ", Bypass Delay: " + bypassDelay);

        // Step 1: Send base request once per unique request
        core.logger.log("NoSQLI", "Sending base request for URL: " + url);
        HttpRequestResponse baseResp = core.requestSender.sendRequest(request, "", false, bypassDelay);
        int baseStatus = baseResp.response() != null ? baseResp.response().statusCode() : 0;
        int baseLength = baseResp.response() != null ? baseResp.response().bodyToString().length() : 0;

        // Check for 500 Internal Server Error on base request
        if (baseResp.response() != null && baseResp.response().statusCode() == 500) {
            core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for base request");
            Annotations annotations = Annotations.annotations()
                    .withHighlightColor(HighlightColor.ORANGE)
                    .withNotes("500 Internal Server Error detected in base request for URL: " + url + "\n" +
                               "This may indicate a potential issue but is not a confirmed vulnerability.");
            core.getApi().siteMap().add(baseResp.withAnnotations(annotations));
            return;
        }

        // Handle standard parameters (including GET parameters with [$eq], [$ne])
        boolean hasStandardParameters = false;
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() == HttpParameterType.JSON) {
                core.logger.log("NoSQLI", "Skipping JSON parameter: " + parameter.name());
                continue;
            }
            if (parameter.type() == HttpParameterType.COOKIE && !core.uiManager.getConfig().isTestCookies()) {
                core.logger.log("NoSQLI", "Skipping COOKIE parameter due to toggle: " + parameter.name());
                continue;
            }
            hasStandardParameters = true;

            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            // Step 2: Test with $eq injection
            String eqPayload = formatPayload(value, "$eq");
            String encodedEqPayload = core.getApi().utilities().urlUtils().encode(eqPayload);
            HttpParameter eqParam = HttpParameter.parameter(name, encodedEqPayload, type);
            HttpRequest eqReq = request.withUpdatedParameters(eqParam);
            core.logger.log("NoSQLI", "Sending $eq payload for parameter: " + name + ", Payload: " + eqPayload + ", Encoded Payload: " + encodedEqPayload + ", Full URL: " + eqReq.url());
            HttpRequestResponse eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
            int eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
            int eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;

            // Log response details
            core.logger.log("NoSQLI", "Response for $eq payload on " + name + ": Status=" + eqStatus + ", Length=" + eqLength);

            // Handle 400 Bad Request by retrying with stringified payload
            if (eqResp.response() != null && eqResp.response().statusCode() == 400) {
                String stringifiedEqPayload = eqPayload.replace("\"", "\\\"");
                String encodedStringifiedEqPayload = core.getApi().utilities().urlUtils().encode(stringifiedEqPayload);
                eqParam = HttpParameter.parameter(name, encodedStringifiedEqPayload, type);
                eqReq = request.withUpdatedParameters(eqParam);
                core.logger.log("NoSQLI", "Received 400 Bad Request, retrying with stringified $eq payload: " + stringifiedEqPayload + ", Full URL: " + eqReq.url());
                eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
                eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
                eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;
                core.logger.log("NoSQLI", "Response after stringified $eq payload on " + name + ": Status=" + eqStatus + ", Length=" + eqLength);
            }

            // Check for 500 Internal Server Error on $eq request
            if (eqResp.response() != null && eqResp.response().statusCode() == 500) {
                core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with $eq payload: " + eqPayload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.ORANGE)
                        .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                   "Payload: " + eqPayload + "\n" +
                                   "Encoded Payload: " + encodedEqPayload + "\n" +
                                   "This may indicate a potential issue but is not a confirmed vulnerability.");
                core.getApi().siteMap().add(eqResp.withAnnotations(annotations));
                continue;
            }

            // Step 3: Test with $ne injection
            String nePayload = formatPayload(value, "$ne");
            String encodedNePayload = core.getApi().utilities().urlUtils().encode(nePayload);
            HttpParameter neParam = HttpParameter.parameter(name, encodedNePayload, type);
            HttpRequest neReq = request.withUpdatedParameters(neParam);
            core.logger.log("NoSQLI", "Sending $ne payload for parameter: " + name + ", Payload: " + nePayload + ", Encoded Payload: " + encodedNePayload + ", Full URL: " + neReq.url());
            HttpRequestResponse neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
            int neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
            int neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;

            // Log response details
            core.logger.log("NoSQLI", "Response for $ne payload on " + name + ": Status=" + neStatus + ", Length=" + neLength);

            // Handle 400 Bad Request by retrying with stringified payload
            if (neResp.response() != null && neResp.response().statusCode() == 400) {
                String stringifiedNePayload = nePayload.replace("\"", "\\\"");
                String encodedStringifiedNePayload = core.getApi().utilities().urlUtils().encode(stringifiedNePayload);
                neParam = HttpParameter.parameter(name, encodedStringifiedNePayload, type);
                neReq = request.withUpdatedParameters(neParam);
                core.logger.log("NoSQLI", "Received 400 Bad Request, retrying with stringified $ne payload: " + stringifiedNePayload + ", Full URL: " + neReq.url());
                neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
                neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
                neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;
                core.logger.log("NoSQLI", "Response after stringified $ne payload on " + name + ": Status=" + neStatus + ", Length=" + neLength);
            }

            // Check for 500 Internal Server Error on $ne request
            if (neResp.response() != null && neResp.response().statusCode() == 500) {
                core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for parameter: " + name + " with $ne payload: " + nePayload);
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.ORANGE)
                        .withNotes("500 Internal Server Error detected in parameter: " + name + "\n" +
                                   "Payload: " + nePayload + "\n" +
                                   "Encoded Payload: " + encodedNePayload + "\n" +
                                   "This may indicate a potential issue but is not a confirmed vulnerability.");
                core.getApi().siteMap().add(neResp.withAnnotations(annotations));
                continue;
            }

            // Step 4: Compare status codes
            if (baseStatus != eqStatus || eqStatus != neStatus || baseStatus == 0) {
                core.logger.log("NoSQLI", "Status codes differ or are zero for parameter: " + name + " (Base=" + baseStatus + ", $eq=" + eqStatus + ", $ne=" + neStatus + "). Skipping parameter.");
                continue;
            }

            // Step 5: Compare base and $eq response lengths
            boolean isVulnerable = false;
            if (baseLength == eqLength) {
                // Step 6: Compare $ne response length with $eq
                if (neLength != eqLength) {
                    isVulnerable = true;
                    core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected for parameter: " + name + ", $ne payload: " + nePayload);
                }
            } else {
                // Step 7: Fallback check
                if (neLength != eqLength) {
                    isVulnerable = true;
                    core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected (fallback) for parameter: " + name + ", $ne payload: " + nePayload);
                }
            }

            if (isVulnerable) {
                Annotations annotations = Annotations.annotations()
                        .withHighlightColor(HighlightColor.RED)
                        .withNotes("NoSQL Injection detected in parameter: " + name + "\n" +
                                   "Base Value: " + value + "\n" +
                                   "$eq Payload: " + eqPayload + "\n" +
                                   "$ne Payload: " + nePayload + "\n" +
                                   "Base Status: " + baseStatus + ", Length: " + baseLength + "\n" +
                                   "$eq Status: " + eqStatus + ", Length: " + eqLength + "\n" +
                                   "$ne Status: " + neStatus + ", Length: " + neLength);
                core.getApi().siteMap().add(neResp.withAnnotations(annotations));
            } else {
                core.logger.log("NoSQLI", "No vulnerability detected for parameter: " + name);
            }

            // Additional test for GET parameters: Inject [$eq] and [$ne] (e.g., lng[$eq]=en)
            if (type == HttpParameterType.URL) {
                // Remove the original parameter to avoid conflicts
                HttpRequest baseWithoutParam = request.withRemovedParameters(parameter);

                // Test param[$eq]=value (send raw value, e.g., lng[$eq]=en)
                String eqArrayParamName = name + "[$eq]";
                String eqArrayValue = value; // Use the raw value, no JSON formatting
                HttpParameter eqArrayParam = HttpParameter.urlParameter(eqArrayParamName, eqArrayValue);
                HttpRequest eqArrayReq = baseWithoutParam.withAddedParameters(eqArrayParam);
                core.logger.log("NoSQLI", "Sending GET parameter $eq payload: " + eqArrayParamName + "=" + eqArrayValue + ", Full URL: " + eqArrayReq.url());
                HttpRequestResponse eqArrayResp = core.requestSender.sendRequest(eqArrayReq, "", false, bypassDelay);
                int eqArrayStatus = eqArrayResp.response() != null ? eqArrayResp.response().statusCode() : 0;
                int eqArrayLength = eqArrayResp.response() != null ? eqArrayResp.response().bodyToString().length() : 0;

                // Log response details
                core.logger.log("NoSQLI", "Response for GET $eq payload on " + name + ": Status=" + eqArrayStatus + ", Length=" + eqArrayLength);

                // Do not retry with stringified payload for raw GET parameters
                if (eqArrayResp.response() != null && eqArrayResp.response().statusCode() == 500) {
                    core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for GET parameter: " + eqArrayParamName + " with value: " + eqArrayValue);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in GET parameter: " + eqArrayParamName + "\n" +
                                       "Value: " + eqArrayValue + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(eqArrayResp.withAnnotations(annotations));
                    continue;
                }

                // Test param[$ne]=value (send raw value, e.g., lng[$ne]=en)
                String neArrayParamName = name + "[$ne]";
                String neArrayValue = value; // Use the raw value, no JSON formatting
                HttpParameter neArrayParam = HttpParameter.urlParameter(neArrayParamName, neArrayValue);
                HttpRequest neArrayReq = baseWithoutParam.withAddedParameters(neArrayParam);
                core.logger.log("NoSQLI", "Sending GET parameter $ne payload: " + neArrayParamName + "=" + neArrayValue + ", Full URL: " + neArrayReq.url());
                HttpRequestResponse neArrayResp = core.requestSender.sendRequest(neArrayReq, "", false, bypassDelay);
                int neArrayStatus = neArrayResp.response() != null ? neArrayResp.response().statusCode() : 0;
                int neArrayLength = neArrayResp.response() != null ? neArrayResp.response().bodyToString().length() : 0;

                // Log response details
                core.logger.log("NoSQLI", "Response for GET $ne payload on " + name + ": Status=" + neArrayStatus + ", Length=" + neArrayLength);

                // Do not retry with stringified payload for raw GET parameters
                if (neArrayResp.response() != null && neArrayResp.response().statusCode() == 500) {
                    core.logger.log("NoSQLI", "[ERROR] 500 Internal Server Error detected for GET parameter: " + neArrayParamName + " with value: " + neArrayValue);
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.ORANGE)
                            .withNotes("500 Internal Server Error detected in GET parameter: " + neArrayParamName + "\n" +
                                       "Value: " + neArrayValue + "\n" +
                                       "This may indicate a potential issue but is not a confirmed vulnerability.");
                    core.getApi().siteMap().add(neArrayResp.withAnnotations(annotations));
                    continue;
                }

                // Step 4: Compare status codes for GET parameters
                // Relaxed condition: Allow detection to proceed even if status codes differ slightly
                if (baseStatus == 0) {
                    core.logger.log("NoSQLI", "Base status code is zero for GET parameter: " + name + ". Skipping parameter.");
                    continue;
                }

                // Step 5: Compare base and $eq response lengths for GET parameters
                isVulnerable = false;
                if (baseLength == eqArrayLength) {
                    // Step 6: Compare $ne response length with $eq
                    if (neArrayLength != eqArrayLength) {
                        isVulnerable = true;
                        core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected for GET parameter: " + name + ", $ne payload: " + neArrayParamName + "=" + neArrayValue);
                    }
                } else {
                    // Step 7: Fallback check
                    if (neArrayLength != eqArrayLength) {
                        isVulnerable = true;
                        core.logger.log("NoSQLI", "[VULNERABLE] NoSQL Injection detected (fallback) for GET parameter: " + name + ", $ne payload: " + neArrayParamName + "=" + neArrayValue);
                    }
                }

                if (isVulnerable) {
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.RED)
                            .withNotes("NoSQL Injection detected in GET parameter: " + name + "\n" +
                                       "Base Value: " + value + "\n" +
                                       "$eq Payload: " + eqArrayParamName + "=" + eqArrayValue + "\n" +
                                       "$ne Payload: " + neArrayParamName + "=" + neArrayValue + "\n" +
                                       "Base Status: " + baseStatus + ", Length: " + baseLength + "\n" +
                                       "$eq Status: " + eqArrayStatus + ", Length: " + eqArrayLength + "\n" +
                                       "$ne Status: " + neArrayStatus + ", Length: " + neArrayLength);
                    core.getApi().siteMap().add(neArrayResp.withAnnotations(annotations));
                } else {
                    core.logger.log("NoSQLI", "No vulnerability detected for GET parameter: " + name);
                }
            }
        }

        if (!hasStandardParameters) {
            core.logger.log("NoSQLI", "No standard parameters found to test");
        }

        // Handle JSON parameters for POST/PUT
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            String contentType = request.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                core.logger.log("NoSQLI", "Detected JSON request");
                String body = request.bodyToString();
                if (body.isEmpty()) {
                    core.logger.log("NoSQLI", "Empty JSON body, skipping JSON testing");
                } else {
                    try {
                        JSONObject jsonObject = new JSONObject(body);
                        processJsonNode(jsonObject, "", url, request, baseResp, bypassDelay);
                    } catch (JSONException e) {
                        core.logger.logError("NoSQLI", "Failed to parse JSON body: " + e.getMessage());
                    }
                }
            } else {
                core.logger.log("NoSQLI", "Non-JSON Content-Type, skipping JSON testing");
            }
        }

        core.logger.log("NoSQLI", "Completed NoSQL Injection testing for URL: " + url);
    }

    public void runContextMenuNoSQLITest(HttpRequestResponse requestResponse) {
        core.logger.log("CONTEXT", "=== Starting NoSQL Injection Test from context menu ===");
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
                    ", NoSQLI Toggle=" + core.uiManager.getConfig().getCheckers().getOrDefault("NoSQLI", false) +
                    ", Cookie Testing=" + core.uiManager.getConfig().isTestCookies() +
                    ", Excluded Extensions=" + core.uiManager.getConfig().getExcludedExtensions() +
                    ", Method Allowed=" + core.uiManager.getConfig().isMethodAllowed(method) +
                    ", Delay=" + core.uiManager.getConfig().getDelayMillis() + "ms");

            // Temporarily override settings for context menu test
            boolean originalCookieTesting = core.uiManager.getConfig().isTestCookies();
            core.uiManager.getConfig().setTestCookies(true); // Always test cookies
            boolean originalNoSQLIToggle = core.uiManager.getConfig().getCheckers().getOrDefault("NoSQLI", false);
            core.uiManager.getConfig().getCheckers().put("NoSQLI", true); // Force NoSQLI testing

            // Run NoSQLI test with delay bypassed
            checkForNoSQLI(request, true); // Use the HttpRequest overload

            // Restore original settings
            core.uiManager.getConfig().setTestCookies(originalCookieTesting);
            core.uiManager.getConfig().getCheckers().put("NoSQLI", originalNoSQLIToggle);

            core.logger.log("CONTEXT", "=== Completed NoSQL Injection Test ===");
        } catch (Exception e) {
            core.logger.logError("CONTEXT", "Error in context menu NoSQLI test: " + e.getMessage());
        }
    }

    private void processJsonNode(Object node, String path, String url, HttpRequest originalRequest, HttpRequestResponse baseResp, boolean bypassDelay) {
        core.logger.log("JSON", "Processing node at path: " + (path.isEmpty() ? "<root>" : path));
        if (node instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) node;
            for (String key : jsonObject.keySet()) {
                String newPath = path.isEmpty() ? key : path + "." + key;
                processJsonNode(jsonObject.get(key), newPath, url, originalRequest, baseResp, bypassDelay);
            }
        } else if (node instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) node;
            // Always test index [0], even if the array is empty
            String newPath = path + "[0]";
            testJsonPath(newPath, url, originalRequest, baseResp, bypassDelay, jsonArray.length() == 0);
            // Process non-empty arrays
            for (int i = 0; i < jsonArray.length(); i++) {
                newPath = path + "[" + i + "]";
                processJsonNode(jsonArray.get(i), newPath, url, originalRequest, baseResp, bypassDelay);
            }
        } else {
            testJsonPath(path, url, originalRequest, baseResp, bypassDelay, false);
        }
    }

    private void testJsonPath(String path, String url, HttpRequest originalRequest, HttpRequestResponse baseResp, boolean bypassDelay, boolean isEmptyArray) {
        int baseStatus = baseResp.response() != null ? baseResp.response().statusCode() : 0;
        int baseLength = baseResp.response() != null ? baseResp.response().bodyToString().length() : 0;

        JSONObject modifiedJson = new JSONObject(originalRequest.bodyToString());
        Object value = getJsonValue(modifiedJson, path);
        // For empty arrays, value will be null at index [0]; use null as injected value
        String baseValueStr = isEmptyArray ? "null" : (value != null ? value.toString() : "null");

        // Special case: JSON array parameters
        Object injectionValue = isEmptyArray ? null : value;

        // Step 2: Test with $eq injection
        String eqPayload = formatJsonPayload(injectionValue, "$eq");
        HttpRequestResponse eqResp = null;
        int eqStatus = 0;
        int eqLength = 0;
        boolean usedStringifiedEqPayload = false;

        if (setJsonValue(modifiedJson, path, new JSONObject(eqPayload))) {
            HttpRequest eqReq = originalRequest.withBody(modifiedJson.toString());
            core.logger.log("JSON", "Sending $eq JSON payload for: " + path + ", Payload: " + eqPayload);
            eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
            eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
            eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;

            // Handle 400 Bad Request by retrying with stringified payload
            if (eqStatus == 400) {
                String stringifiedEqPayload = eqPayload.replace("\"", "\\\"");
                if (setJsonValue(modifiedJson, path, stringifiedEqPayload)) {
                    core.logger.log("JSON", "Received 400 Bad Request for $eq payload, retrying with stringified payload: " + stringifiedEqPayload);
                    eqReq = originalRequest.withBody(modifiedJson.toString());
                    eqResp = core.requestSender.sendRequest(eqReq, "", false, bypassDelay);
                    eqStatus = eqResp.response() != null ? eqResp.response().statusCode() : 0;
                    eqLength = eqResp.response() != null ? eqResp.response().bodyToString().length() : 0;
                    usedStringifiedEqPayload = true;
                }
            }
        } else {
            core.logger.log("JSON", "Failed to set $eq payload for: " + path);
            return;
        }

        if (eqResp.response() != null && eqResp.response().statusCode() == 500) {
            core.logger.log("JSON", "[ERROR] 500 Internal Server Error detected for JSON parameter: " + path + " with $eq payload: " + (usedStringifiedEqPayload ? eqPayload.replace("\"", "\\\"") : eqPayload));
            Annotations annotations = Annotations.annotations()
                    .withHighlightColor(HighlightColor.ORANGE)
                    .withNotes("500 Internal Server Error detected in JSON parameter: " + path + "\n" +
                               "Payload: " + (usedStringifiedEqPayload ? eqPayload.replace("\"", "\\\"") : eqPayload) + "\n" +
                               "This may indicate a potential issue but is not a confirmed vulnerability.");
            core.getApi().siteMap().add(eqResp.withAnnotations(annotations));
            return;
        }

        // Step 3: Test with $ne injection
        String nePayload = formatJsonPayload(injectionValue, "$ne");
        HttpRequestResponse neResp = null;
        int neStatus = 0;
        int neLength = 0;
        boolean usedStringifiedNePayload = usedStringifiedEqPayload;

        if (usedStringifiedEqPayload) {
            String stringifiedNePayload = nePayload.replace("\"", "\\\"");
            if (setJsonValue(modifiedJson, path, stringifiedNePayload)) {
                HttpRequest neReq = originalRequest.withBody(modifiedJson.toString());
                core.logger.log("JSON", "Sending $ne JSON payload for: " + path + ", Payload: " + stringifiedNePayload);
                neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
                neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
                neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;
                usedStringifiedNePayload = true;
            }
        } else {
            if (setJsonValue(modifiedJson, path, new JSONObject(nePayload))) {
                HttpRequest neReq = originalRequest.withBody(modifiedJson.toString());
                core.logger.log("JSON", "Sending $ne JSON payload for: " + path + ", Payload: " + nePayload);
                neResp = core.requestSender.sendRequest(neReq, "", false, bypassDelay);
                neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
                neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;

                // Handle 400 Bad Request by retrying with stringified payload
                if (neStatus == 400) {
                    String stringifiedNePayload = nePayload.replace("\"", "\\\"");
                    if (setJsonValue(modifiedJson, path, stringifiedNePayload)) {
                        core.logger.log("JSON", "Received 400 Bad Request for $ne payload, retrying with stringified payload: " + stringifiedNePayload);
                        HttpRequest neReqRetry = originalRequest.withBody(modifiedJson.toString());
                        neResp = core.requestSender.sendRequest(neReqRetry, "", false, bypassDelay);
                        neStatus = neResp.response() != null ? neResp.response().statusCode() : 0;
                        neLength = neResp.response() != null ? neResp.response().bodyToString().length() : 0;
                        usedStringifiedNePayload = true;
                    }
                }
            }
        }

        if (neResp == null) {
            core.logger.log("JSON", "Failed to set $ne payload for: " + path);
            return;
        }

        if (neResp.response() != null && neResp.response().statusCode() == 500) {
            core.logger.log("JSON", "[ERROR] 500 Internal Server Error detected for JSON parameter: " + path + " with $ne payload: " + (usedStringifiedNePayload ? nePayload.replace("\"", "\\\"") : nePayload));
            Annotations annotations = Annotations.annotations()
                    .withHighlightColor(HighlightColor.ORANGE)
                    .withNotes("500 Internal Server Error detected in JSON parameter: " + path + "\n" +
                               "Payload: " + (usedStringifiedNePayload ? nePayload.replace("\"", "\\\"") : nePayload) + "\n" +
                               "This may indicate a potential issue but is not a confirmed vulnerability.");
            core.getApi().siteMap().add(neResp.withAnnotations(annotations));
            return;
        }

        // Step 4: Compare status codes
        if (baseStatus != eqStatus || eqStatus != neStatus || baseStatus == 0) {
            core.logger.log("JSON", "Status codes differ or are zero for JSON parameter: " + path + " (Base=" + baseStatus + ", $eq=" + eqStatus + ", $ne=" + neStatus + "). Skipping parameter.");
            return;
        }

        // Step 5: Compare base and $eq response lengths
        boolean isVulnerable = false;
        if (baseLength == eqLength) {
            // Step 6: Compare $ne response length with $eq
            if (neLength != eqLength) {
                isVulnerable = true;
                core.logger.log("JSON", "[VULNERABLE] NoSQL Injection detected for JSON parameter: " + path + ", $ne payload: " + (usedStringifiedNePayload ? nePayload.replace("\"", "\\\"") : nePayload));
            }
        } else {
            // Step 7: Fallback check
            if (neLength != eqLength) {
                isVulnerable = true;
                core.logger.log("JSON", "[VULNERABLE] NoSQL Injection detected (fallback) for JSON parameter: " + path + ", $ne payload: " + (usedStringifiedNePayload ? nePayload.replace("\"", "\\\"") : nePayload));
            }
        }

        if (isVulnerable) {
            Annotations annotations = Annotations.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes("NoSQL Injection detected in JSON parameter: " + path + "\n" +
                               "Base Value: " + baseValueStr + "\n" +
                               "$eq Payload: " + (usedStringifiedEqPayload ? eqPayload.replace("\"", "\\\"") : eqPayload) + "\n" +
                               "$ne Payload: " + (usedStringifiedNePayload ? nePayload.replace("\"", "\\\"") : nePayload) + "\n" +
                               "Base Status: " + baseStatus + ", Length: " + baseLength + "\n" +
                               "$eq Status: " + eqStatus + ", Length: " + eqLength + "\n" +
                               "$ne Status: " + neStatus + ", Length: " + neLength);
            core.getApi().siteMap().add(neResp.withAnnotations(annotations));
        } else {
            core.logger.log("JSON", "No vulnerability detected for JSON parameter: " + path);
        }
    }

    // Helper method to format payloads for query parameters
    private String formatPayload(String value, String operator) {
        // Check for numeric
        if (value.matches("-?\\d+(\\.\\d+)?")) {
            return "{\"" + operator + "\":" + value + "}";
        }
        // Check for boolean
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) {
            return "{\"" + operator + "\":" + value.toLowerCase() + "}";
        }
        // Check for null
        if (value.equalsIgnoreCase("null")) {
            return "{\"" + operator + "\":null}";
        }
        // Default: treat as string
        return "{\"" + operator + "\":\"" + value + "\"}";
    }

    // Helper method to format payloads for JSON body (raw JSON format)
    private String formatJsonPayload(Object value, String operator) {
        if (value == null || value == JSONObject.NULL) {
            return "{\"" + operator + "\":null}";
        } else if (value instanceof Number) {
            return "{\"" + operator + "\":" + value + "}";
        } else if (value instanceof Boolean) {
            return "{\"" + operator + "\":" + value.toString().toLowerCase() + "}";
        } else {
            return "{\"" + operator + "\":\"" + value + "\"}";
        }
    }

    private Object getJsonValue(JSONObject jsonObject, String path) {
        try {
            List<String> parts = new ArrayList<>();
            Matcher matcher = Pattern.compile("\\w+|\\d+").matcher(path.replaceAll("\\.", " ").replaceAll("\\[", " ").replaceAll("\\]", ""));
            while (matcher.find()) {
                parts.add(matcher.group());
            }

            Object current = jsonObject;
            for (int i = 0; i < parts.size(); i++) {
                String part = parts.get(i);
                if (current instanceof JSONObject) {
                    current = ((JSONObject) current).get(part);
                } else if (current instanceof JSONArray) {
                    int index = Integer.parseInt(part);
                    if (index >= ((JSONArray) current).length()) {
                        return null; // Out of bounds, treat as null
                    }
                    current = ((JSONArray) current).get(index);
                } else {
                    core.logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getClass().getSimpleName());
                    return null;
                }
            }
            return current;
        } catch (Exception e) {
            core.logger.logError("JSON", "Failed to get value at: " + path + ", error: " + e.getMessage());
            return null;
        }
    }

    private boolean setJsonValue(JSONObject jsonObject, String path, Object value) {
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
                    if (currentArray.get(index) == null) {
                        currentArray.put(index, ""); // Default to empty string for empty array indices
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

package whoami.checkers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import whoami.core.CoreModules;

public class SQLiChecker {
    private final CoreModules core;

    public SQLiChecker(CoreModules core) {
        this.core = core;
    }

    public void checkForSQLi(HttpRequest request) {
        for (HttpParameter parameter : request.parameters()) {
            String name = parameter.name();
            String value = parameter.value();
            HttpParameterType type = parameter.type();

            // Step 1: Add single quote
            HttpParameter paramWithSingleQuote = HttpParameter.parameter(name, value + "'", type);
            HttpRequest singleQuoteRequest = request.withUpdatedParameters(paramWithSingleQuote);
            // Updated sendRequest call: assuming default session and no redirects
            HttpRequestResponse singleQuoteResponse = core.requestSender.sendRequest(singleQuoteRequest, "", false);
            int code1 = singleQuoteResponse.response().statusCode();

            Annotations annotations500 = Annotations.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes("SQL Injection test: Single quote caused 500 error in parameter: " + name);

            if (code1 == 500) {
                core.siteMap().add(singleQuoteResponse.withAnnotations(annotations500));

                // Step 2: Try double single quote
                HttpParameter paramWithDoubleQuotes = HttpParameter.parameter(name, value + "''", type);
                HttpRequest doubleQuoteRequest = request.withUpdatedParameters(paramWithDoubleQuotes);
                // Updated sendRequest call
                HttpRequestResponse doubleQuoteResponse = core.requestSender.sendRequest(doubleQuoteRequest, "", false);
                int code2 = doubleQuoteResponse.response().statusCode();

                if (code2 == 200) {
                    core.logger.logToOutput("[SQLi FOUND] Parameter: " + name + " at: " + request.url().toString());
                    Annotations annotations = Annotations.annotations()
                            .withHighlightColor(HighlightColor.RED)
                            .withNotes("SQL Injection found in parameter: " + name + "\n" +
                                       "Single quote caused 500 error, double quotes returned 200 OK.");
                    core.siteMap().add(doubleQuoteResponse.withAnnotations(annotations));
                }
            }
        }
    }
}

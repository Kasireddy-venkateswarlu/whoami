package whoami.core;

import burp.api.montoya.MontoyaApi;

public class Logger {
    private final MontoyaApi api;

    public Logger(MontoyaApi api) {
        this.api = api;
    }

    public void logToOutput(String message) {
        api.logging().logToOutput(message);
    }

    public void log(String context, String message) {
        api.logging().logToOutput("[" + context + "] " + message);
    }

    public void logError(String context, String message) {
        api.logging().logToError("[" + context + "] ERROR: " + message);
    }
}

// core/Logger.java
package whoami.core;

import burp.api.montoya.logging.Logging;

public class Logger {
    private final Logging logging;

    public Logger(Logging logging) {
        this.logging = logging;
    }

    public void log(String category, String message) {
        logging.logToOutput("[" + category + "] " + message);
    }

    public void logError(String category, String message) {
        logging.logToError("[" + category + "] " + message);
    }

    public void logToOutput(String message) {
        logging.logToOutput(message);
    }
}

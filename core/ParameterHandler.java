package whoami.core;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public class ParameterHandler {
    private final Logger logger;
    private final ObjectMapper mapper = new ObjectMapper();

    public ParameterHandler(Logger logger) {
        this.logger = logger;
    }

    public HttpParameter updateParameter(HttpParameter param, String value) {
        if (param.type() == HttpParameterType.JSON) {
            try {
                return updateJsonParameter(param, value);
            } catch (Exception e) {
                logger.logError("JSON", "Failed to update JSON parameter: " + param.name() + ", error: " + e.getMessage());
                return param;
            }
        }
        if (param.type() == HttpParameterType.COOKIE) {
            logger.log("PARAM", "Skipping COOKIE parameter: " + param.name());
            return param;
        }
        return HttpParameter.parameter(param.name(), value, param.type());
    }

    private HttpParameter updateJsonParameter(HttpParameter param, String value) {
        String path = param.name();
        String jsonString = param.value();

        try {
            JsonNode rootNode = mapper.readTree(jsonString);
            ObjectNode modifiedNode = (ObjectNode) rootNode.deepCopy();

            // Navigate to the target path
            JsonNode currentNode = modifiedNode;
            String[] parts = path.split("\\.");
            for (int i = 0; i < parts.length - 1; i++) {
                String part = parts[i];
                if (currentNode.isObject() && currentNode.has(part)) {
                    currentNode = currentNode.get(part);
                } else {
                    logger.logError("JSON", "Invalid object key at path: " + path);
                    return param;
                }
            }

            String lastPart = parts[parts.length - 1];
            if (currentNode.isObject() && currentNode.has(lastPart)) {
                ((ObjectNode) currentNode).put(lastPart, value);
            } else {
                logger.logError("JSON", "Invalid object key at path: " + path);
                return param;
            }

            // Serialize the modified JSON
            String modifiedJson = mapper.writeValueAsString(modifiedNode);
            logger.log("JSON", "Updated JSON parameter: " + path + ", new value: " + value);
            return HttpParameter.parameter(param.name(), modifiedJson, HttpParameterType.JSON);
        } catch (Exception e) {
            logger.logError("JSON", "Failed to parse JSON: " + path + ", error: " + e.getMessage());
            return param;
        }
    }
}

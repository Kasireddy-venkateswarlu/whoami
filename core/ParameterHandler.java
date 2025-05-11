package whoami.core;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class ParameterHandler {
    private final Logger logger;

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
            JSONObject jsonObject = new JSONObject(jsonString);
            setJsonValue(jsonObject, path, value);
            return HttpParameter.parameter(param.name(), jsonObject.toString(), HttpParameterType.JSON);
        } catch (JSONException e) {
            logger.logError("JSON", "Failed to parse JSON: " + path + ", error: " + e.getMessage());
            return param;
        }
    }

    private void setJsonValue(JSONObject json, String path, String value) {
        try {
            String[] parts = path.split("\\.");
            Object current = json;

            for (int i = 0; i < parts.length - 1; i++) {
                String part = parts[i];
                if (part.contains("[")) {
                    String arrayPart = part.substring(0, part.indexOf("["));
                    int index = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                    JSONArray array = current instanceof JSONObject ? ((JSONObject) current).optJSONArray(arrayPart) : (JSONArray) current;
                    if (array == null) {
                        array = new JSONArray();
                        ((JSONObject) current).put(arrayPart, array);
                    }
                    while (array.length() <= index) {
                        array.put((Object) null); // Cast null to Object
                    }
                    current = array;
                } else {
                    if (!(current instanceof JSONObject)) {
                        logger.logError("JSON", "Invalid structure at: " + path + ", found: " + current.getClass().getSimpleName());
                        return;
                    }
                    JSONObject obj = (JSONObject) current;
                    if (!obj.has(part)) {
                        obj.put(part, new JSONObject());
                    }
                    current = obj.get(part);
                }
            }

            String lastPart = parts[parts.length - 1];
            if (lastPart.contains("[")) {
                String arrayPart = lastPart.substring(0, lastPart.indexOf("["));
                int index = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
                JSONArray array = current instanceof JSONObject ? ((JSONObject) current).optJSONArray(arrayPart) : (JSONArray) current;
                if (array == null) {
                    array = new JSONArray();
                    ((JSONObject) current).put(arrayPart, array);
                }
                while (array.length() <= index) {
                    array.put((Object) null); // Cast null to Object
                }
                array.put(index, value);
            } else {
                ((JSONObject) current).put(lastPart, value);
            }
        } catch (Exception e) {
            logger.logError("JSON", "Failed to set value at: " + path + ", error: " + e.getMessage());
        }
    }
}

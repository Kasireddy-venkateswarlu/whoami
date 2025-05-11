package whoami.core;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
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
            jsonObject.put(path, value);
            return HttpParameter.parameter(param.name(), jsonObject.toString(), HttpParameterType.JSON);
        } catch (JSONException e) {
            logger.logError("JSON", "Failed to parse JSON: " + path + ", error: " + e.getMessage());
            return param;
        }
    }
}

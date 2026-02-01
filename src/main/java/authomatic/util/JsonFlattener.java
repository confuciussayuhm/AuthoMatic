package authomatic.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Flattens JSON objects to dot-notation key-value pairs.
 * Handles nested objects and arrays with configurable limits.
 */
public class JsonFlattener {

    private static final int MAX_DEPTH = 10;
    private static final int MAX_ITEMS = 100;

    /**
     * Flatten a JSON string to a map of dot-notation paths to values.
     *
     * @param json The JSON string to flatten
     * @return Map of paths to string values, or empty map if parsing fails
     */
    public static Map<String, String> flatten(String json) {
        Map<String, String> result = new LinkedHashMap<>();

        if (json == null || json.trim().isEmpty()) {
            return result;
        }

        try {
            JsonElement root = JsonParser.parseString(json);
            flattenElement(root, "", result, 0);
        } catch (JsonSyntaxException e) {
            // Not valid JSON, return empty map
        }

        return result;
    }

    /**
     * Check if a string is valid JSON.
     *
     * @param json The string to check
     * @return true if the string is valid JSON
     */
    public static boolean isValidJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return false;
        }

        try {
            JsonParser.parseString(json);
            return true;
        } catch (JsonSyntaxException e) {
            return false;
        }
    }

    private static void flattenElement(JsonElement element, String prefix, Map<String, String> result, int depth) {
        if (depth > MAX_DEPTH || result.size() >= MAX_ITEMS) {
            return;
        }

        if (element.isJsonNull()) {
            // Skip null values
            return;
        }

        if (element.isJsonPrimitive()) {
            String value = element.getAsString();
            if (!value.isEmpty()) {
                result.put(prefix, value);
            }
            return;
        }

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                if (result.size() >= MAX_ITEMS) {
                    return;
                }
                String key = entry.getKey();
                String newPrefix = prefix.isEmpty() ? key : prefix + "." + key;
                flattenElement(entry.getValue(), newPrefix, result, depth + 1);
            }
            return;
        }

        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) {
                if (result.size() >= MAX_ITEMS) {
                    return;
                }
                String newPrefix = prefix + "[" + i + "]";
                flattenElement(array.get(i), newPrefix, result, depth + 1);
            }
        }
    }
}

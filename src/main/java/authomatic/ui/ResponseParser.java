package authomatic.ui;

import authomatic.config.TokenExtractionConfig;
import authomatic.util.HttpParser;
import authomatic.util.JsonFlattener;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses HTTP responses into selectable items for the token dropdown.
 * Extracts headers, cookies, and JSON body values.
 */
public class ResponseParser {

    // Standard headers to filter out (not typically containing tokens)
    private static final Set<String> STANDARD_HEADERS = new HashSet<>(Arrays.asList(
            "content-type", "content-length", "content-encoding",
            "date", "server", "connection", "keep-alive",
            "cache-control", "pragma", "expires",
            "vary", "accept-ranges", "age",
            "etag", "last-modified",
            "transfer-encoding", "x-powered-by",
            "strict-transport-security", "x-content-type-options",
            "x-frame-options", "x-xss-protection",
            "access-control-allow-origin", "access-control-allow-methods",
            "access-control-allow-headers", "access-control-allow-credentials",
            "access-control-max-age", "access-control-expose-headers"
    ));

    /**
     * Parse a raw HTTP response into selectable items.
     *
     * @param rawResponse The raw HTTP response text
     * @return List of ParsedValueItem objects, including category headers
     */
    public static List<ParsedValueItem> parse(String rawResponse) {
        List<ParsedValueItem> items = new ArrayList<>();

        if (rawResponse == null || rawResponse.trim().isEmpty()) {
            return items;
        }

        HttpParser.ParsedResponse parsed = HttpParser.parseResponse(rawResponse);
        if (parsed == null) {
            return items;
        }

        // Parse interesting headers
        List<ParsedValueItem> headerItems = parseHeaders(parsed);
        if (!headerItems.isEmpty()) {
            items.add(ParsedValueItem.category("Headers"));
            items.addAll(headerItems);
        }

        // Parse cookies from Set-Cookie headers
        List<ParsedValueItem> cookieItems = parseCookies(parsed);
        if (!cookieItems.isEmpty()) {
            items.add(ParsedValueItem.category("Cookies"));
            items.addAll(cookieItems);
        }

        // Parse JSON body
        List<ParsedValueItem> jsonItems = parseJsonBody(parsed);
        if (!jsonItems.isEmpty()) {
            items.add(ParsedValueItem.category("JSON Body"));
            items.addAll(jsonItems);
        } else if (parsed.body != null && !parsed.body.trim().isEmpty()) {
            // Body exists but isn't JSON
            items.add(ParsedValueItem.category("JSON Body"));
            items.add(ParsedValueItem.value(
                    TokenExtractionConfig.SourceType.JSON_BODY,
                    "(not JSON)",
                    "(Body is not JSON)"
            ));
        }

        return items;
    }

    private static List<ParsedValueItem> parseHeaders(HttpParser.ParsedResponse parsed) {
        List<ParsedValueItem> items = new ArrayList<>();

        for (Map.Entry<String, String> entry : parsed.headers.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();

            // Skip standard headers and Set-Cookie (handled separately)
            if (STANDARD_HEADERS.contains(name.toLowerCase()) ||
                    name.equalsIgnoreCase("Set-Cookie")) {
                continue;
            }

            // Skip empty values
            if (value == null || value.trim().isEmpty()) {
                continue;
            }

            items.add(ParsedValueItem.value(
                    TokenExtractionConfig.SourceType.HEADER,
                    name,
                    value
            ));
        }

        return items;
    }

    private static List<ParsedValueItem> parseCookies(HttpParser.ParsedResponse parsed) {
        List<ParsedValueItem> items = new ArrayList<>();

        for (String setCookie : parsed.setCookies) {
            // Parse "name=value; attributes..."
            int equalsIdx = setCookie.indexOf('=');
            if (equalsIdx <= 0) {
                continue;
            }

            String cookieName = setCookie.substring(0, equalsIdx).trim();
            String rest = setCookie.substring(equalsIdx + 1);

            // Extract just the value part (before semicolon)
            int semicolonIdx = rest.indexOf(';');
            String cookieValue = semicolonIdx > 0 ? rest.substring(0, semicolonIdx) : rest;
            cookieValue = cookieValue.trim();

            // Skip empty values
            if (cookieValue.isEmpty()) {
                continue;
            }

            items.add(ParsedValueItem.value(
                    TokenExtractionConfig.SourceType.COOKIE,
                    cookieName,
                    cookieValue
            ));
        }

        return items;
    }

    private static List<ParsedValueItem> parseJsonBody(HttpParser.ParsedResponse parsed) {
        List<ParsedValueItem> items = new ArrayList<>();

        if (parsed.body == null || parsed.body.trim().isEmpty()) {
            return items;
        }

        // Check if body looks like JSON
        String trimmedBody = parsed.body.trim();
        if (!trimmedBody.startsWith("{") && !trimmedBody.startsWith("[")) {
            // Also check Content-Type
            if (!parsed.isJsonResponse()) {
                return items;
            }
        }

        // Flatten JSON
        Map<String, String> flattened = JsonFlattener.flatten(parsed.body);

        for (Map.Entry<String, String> entry : flattened.entrySet()) {
            items.add(ParsedValueItem.value(
                    TokenExtractionConfig.SourceType.JSON_BODY,
                    entry.getKey(),
                    entry.getValue()
            ));
        }

        return items;
    }
}

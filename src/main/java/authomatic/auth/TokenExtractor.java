package authomatic.auth;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import authomatic.config.HostConfig;
import authomatic.config.TokenExtractionConfig;
import authomatic.config.TokenExtractionConfig.SourceType;
import authomatic.util.Logger;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts authentication tokens from login responses.
 * Supports auto-detection or manual configuration.
 */
public class TokenExtractor {

    // Headers to check for tokens (in priority order)
    private static final List<String> TOKEN_HEADERS = Arrays.asList(
            "Authorization",
            "X-Auth-Token",
            "X-Access-Token",
            "Token"
    );

    // Cookie name patterns that likely contain tokens
    private static final List<String> TOKEN_COOKIE_PATTERNS = Arrays.asList(
            "token", "session", "auth", "jwt", "access"
    );

    // JSON paths to check for tokens (in priority order)
    private static final List<String> TOKEN_JSON_PATHS = Arrays.asList(
            "token",
            "access_token",
            "accessToken",
            "data.token",
            "data.access_token",
            "data.accessToken",
            "response.token",
            "response.access_token",
            "jwt",
            "id_token",
            "idToken"
    );

    private final Logger logger;

    public TokenExtractor(Logger logger) {
        this.logger = logger;
    }

    /**
     * Extracts a token from a login response based on the host configuration.
     * Returns an ExtractedToken or null if no token was found.
     */
    public ExtractedToken extract(HttpResponse response, HostConfig config) {
        TokenExtractionConfig extractionConfig = config.getTokenExtraction();

        if (extractionConfig.isAutoDetect()) {
            return autoDetect(response);
        } else {
            return manualExtract(response, extractionConfig);
        }
    }

    /**
     * Auto-detects the token from the response by checking common sources.
     */
    private ExtractedToken autoDetect(HttpResponse response) {
        // 1. Check headers
        ExtractedToken token = extractFromHeaders(response, TOKEN_HEADERS);
        if (token != null) {
            logger.debug("Auto-detected token in header: " + token.getSourceName());
            return token;
        }

        // 2. Check cookies
        token = extractFromCookies(response, TOKEN_COOKIE_PATTERNS);
        if (token != null) {
            logger.debug("Auto-detected token in cookie: " + token.getSourceName());
            return token;
        }

        // 3. Check JSON body
        token = extractFromJsonBody(response, TOKEN_JSON_PATHS);
        if (token != null) {
            logger.debug("Auto-detected token in JSON body: " + token.getSourceName());
            return token;
        }

        logger.warn("Auto-detection failed to find token in response");
        return null;
    }

    /**
     * Extracts a token using manual configuration.
     */
    private ExtractedToken manualExtract(HttpResponse response, TokenExtractionConfig config) {
        SourceType sourceType = config.getSourceType();
        String name = config.getTokenName();
        String jsonPath = config.getJsonPath();

        ExtractedToken result = null;

        switch (sourceType) {
            case HEADER:
                result = extractFromHeaders(response, Arrays.asList(name));
                break;
            case COOKIE:
                String cookieValue = extractCookieValue(response, name);
                if (cookieValue != null) {
                    result = new ExtractedToken(cookieValue, SourceType.COOKIE, name);
                }
                break;
            case JSON_BODY:
                if (!jsonPath.isEmpty()) {
                    result = extractFromJsonBody(response, Arrays.asList(jsonPath));
                }
                break;
        }

        // Fallback: if extraction failed but we have a manually selected value, use it
        if (result == null && config.hasSelection() && !config.getSelectedValue().isEmpty()) {
            logger.debug("Path-based extraction failed, using stored selection value");
            String sourceName = sourceType == SourceType.JSON_BODY ? jsonPath : name;
            if (sourceName.isEmpty()) {
                sourceName = "manual-selection";
            }
            result = new ExtractedToken(config.getSelectedValue(), sourceType, sourceName);
        }

        if (result == null) {
            logger.warn("Manual extraction failed for " + sourceType + ": " + (name.isEmpty() ? jsonPath : name));
        }

        return result;
    }

    private ExtractedToken extractFromHeaders(HttpResponse response, List<String> headerNames) {
        for (String headerName : headerNames) {
            for (HttpHeader header : response.headers()) {
                if (header.name().equalsIgnoreCase(headerName)) {
                    String value = header.value();
                    // Strip "Bearer " prefix if present
                    if (value.toLowerCase().startsWith("bearer ")) {
                        value = value.substring(7);
                    }
                    if (!value.isEmpty()) {
                        return new ExtractedToken(value, SourceType.HEADER, headerName);
                    }
                }
            }
        }
        return null;
    }

    private ExtractedToken extractFromCookies(HttpResponse response, List<String> patterns) {
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String cookieValue = header.value();
                String cookieName = parseCookieName(cookieValue);
                String value = parseCookieValue(cookieValue);

                if (cookieName != null && value != null) {
                    for (String pattern : patterns) {
                        if (cookieName.toLowerCase().contains(pattern.toLowerCase())) {
                            return new ExtractedToken(value, SourceType.COOKIE, cookieName);
                        }
                    }
                }
            }
        }
        return null;
    }

    private String extractCookieValue(HttpResponse response, String cookieName) {
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String cookieValue = header.value();
                String name = parseCookieName(cookieValue);
                if (name != null && name.equalsIgnoreCase(cookieName)) {
                    return parseCookieValue(cookieValue);
                }
            }
        }
        return null;
    }

    private String parseCookieName(String setCookieHeader) {
        int equalsIndex = setCookieHeader.indexOf('=');
        if (equalsIndex > 0) {
            return setCookieHeader.substring(0, equalsIndex).trim();
        }
        return null;
    }

    private String parseCookieValue(String setCookieHeader) {
        int equalsIndex = setCookieHeader.indexOf('=');
        if (equalsIndex > 0) {
            String rest = setCookieHeader.substring(equalsIndex + 1);
            int semicolonIndex = rest.indexOf(';');
            if (semicolonIndex > 0) {
                return rest.substring(0, semicolonIndex).trim();
            }
            return rest.trim();
        }
        return null;
    }

    private ExtractedToken extractFromJsonBody(HttpResponse response, List<String> jsonPaths) {
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) {
            return null;
        }

        for (String jsonPath : jsonPaths) {
            String value = extractJsonValue(body, jsonPath);
            if (value != null && !value.isEmpty()) {
                return new ExtractedToken(value, SourceType.JSON_BODY, jsonPath);
            }
        }
        return null;
    }

    /**
     * Simple JSON value extraction using regex.
     * Supports paths like "token", "data.token", "data.access_token".
     */
    private String extractJsonValue(String json, String path) {
        String[] parts = path.split("\\.");
        String currentJson = json;

        for (int i = 0; i < parts.length; i++) {
            String key = parts[i];
            boolean isLast = (i == parts.length - 1);

            if (isLast) {
                // Extract the final value (string)
                Pattern pattern = Pattern.compile(
                        "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"",
                        Pattern.CASE_INSENSITIVE
                );
                Matcher matcher = pattern.matcher(currentJson);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            } else {
                // Navigate into nested object
                Pattern pattern = Pattern.compile(
                        "\"" + Pattern.quote(key) + "\"\\s*:\\s*\\{",
                        Pattern.CASE_INSENSITIVE
                );
                Matcher matcher = pattern.matcher(currentJson);
                if (matcher.find()) {
                    int start = matcher.end() - 1;
                    int depth = 0;
                    int end = start;
                    for (int j = start; j < currentJson.length(); j++) {
                        char c = currentJson.charAt(j);
                        if (c == '{') depth++;
                        else if (c == '}') depth--;
                        if (depth == 0) {
                            end = j + 1;
                            break;
                        }
                    }
                    currentJson = currentJson.substring(start, end);
                } else {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Represents an extracted token with its source information.
     */
    public static class ExtractedToken {
        private final String value;
        private final SourceType sourceType;
        private final String sourceName;  // Header name, cookie name, or JSON path

        public ExtractedToken(String value, SourceType sourceType, String sourceName) {
            this.value = value;
            this.sourceType = sourceType;
            this.sourceName = sourceName;
        }

        public String getValue() {
            return value;
        }

        public SourceType getSourceType() {
            return sourceType;
        }

        public String getSourceName() {
            return sourceName;
        }

        @Override
        public String toString() {
            return "Token from " + sourceType + " (" + sourceName + "): " +
                    (value.length() > 20 ? value.substring(0, 20) + "..." : value);
        }
    }
}

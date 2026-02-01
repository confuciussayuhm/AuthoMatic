package authomatic.util;

import authomatic.config.TokenExtractionConfig;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes parsed HTTP request/response and suggests HostConfig values.
 */
public class ImportAnalyzer {

    // Common JSON token field names
    private static final String[] TOKEN_FIELDS = {
            "access_token", "accessToken", "token", "id_token", "idToken",
            "auth_token", "authToken", "jwt", "bearer", "session_token"
    };

    /**
     * Analyze request/response and suggest HostConfig values.
     *
     * @param request  The parsed HTTP request
     * @param response The parsed HTTP response (may be null)
     * @return ImportResult with suggested configuration values
     */
    public static ImportResult analyze(HttpParser.ParsedRequest request, HttpParser.ParsedResponse response) {
        ImportResult result = new ImportResult();

        if (request == null) {
            return result;
        }

        // Extract basic request info
        result.loginUrl = request.buildFullUrl();
        result.method = request.method;
        result.contentType = request.getContentType();
        result.loginBody = request.body;

        // Build suggested URL pattern from host
        String host = request.getHost();
        if (!host.isEmpty()) {
            // Suggest host/** pattern (matches any path on host)
            result.suggestedUrlPattern = host + "/**";
        }

        // Analyze headers for extra headers (e.g., Authorization)
        analyzeHeaders(request, result);

        // Analyze request body for credentials
        analyzeRequestBody(request, result);

        // Analyze response for token extraction
        if (response != null) {
            analyzeResponse(response, result);
        }

        return result;
    }

    /**
     * Analyze request headers and identify extra headers to include.
     */
    private static void analyzeHeaders(HttpParser.ParsedRequest request, ImportResult result) {
        for (Map.Entry<String, String> header : request.headers.entrySet()) {
            String name = header.getKey();
            String value = header.getValue();

            // Skip standard headers that shouldn't be copied
            String lowerName = name.toLowerCase();
            if (lowerName.equals("host") ||
                lowerName.equals("content-type") ||
                lowerName.equals("content-length") ||
                lowerName.equals("connection") ||
                lowerName.equals("accept") ||
                lowerName.equals("accept-encoding") ||
                lowerName.equals("accept-language") ||
                lowerName.equals("user-agent") ||
                lowerName.equals("cache-control") ||
                lowerName.equals("cookie")) {
                continue;
            }

            // Include Authorization headers
            if (lowerName.equals("authorization")) {
                result.extraHeaders.put(name, value);

                // Decode Basic auth to show the user what it contains
                if (value.toLowerCase().startsWith("basic ")) {
                    result.authType = "Basic";
                    try {
                        String encoded = value.substring(6).trim();
                        String decoded = new String(Base64.getDecoder().decode(encoded));
                        result.decodedBasicAuth = decoded;
                    } catch (Exception e) {
                        // Ignore decode errors
                    }
                } else if (value.toLowerCase().startsWith("bearer ")) {
                    result.authType = "Bearer";
                }
            } else {
                // Include other custom headers
                result.extraHeaders.put(name, value);
            }
        }
    }

    /**
     * Analyze request body for credential patterns.
     */
    private static void analyzeRequestBody(HttpParser.ParsedRequest request, ImportResult result) {
        String body = request.body;
        if (body == null || body.isEmpty()) {
            return;
        }

        String contentType = request.getContentType().toLowerCase();

        if (contentType.contains("application/json")) {
            // Check for JSON credentials
            if (body.contains("\"username\"") || body.contains("\"user\"") ||
                body.contains("\"email\"")) {
                result.hasCredentialsInBody = true;
                result.credentialFormat = "JSON";
            }
            if (body.contains("\"password\"") || body.contains("\"passwd\"") ||
                body.contains("\"secret\"")) {
                result.hasCredentialsInBody = true;
            }
        } else if (contentType.contains("application/x-www-form-urlencoded")) {
            // Check for form-encoded credentials
            if (body.contains("username=") || body.contains("user=") ||
                body.contains("email=")) {
                result.hasCredentialsInBody = true;
                result.credentialFormat = "Form";
            }
            if (body.contains("password=") || body.contains("passwd=") ||
                body.contains("secret=")) {
                result.hasCredentialsInBody = true;
            }

            // Check for OAuth2 grant types
            if (body.contains("grant_type=")) {
                Pattern pattern = Pattern.compile("grant_type=([^&]+)");
                Matcher matcher = pattern.matcher(body);
                if (matcher.find()) {
                    result.oauthGrantType = matcher.group(1);
                }
            }
        }
    }

    /**
     * Analyze response for token extraction settings.
     */
    private static void analyzeResponse(HttpParser.ParsedResponse response, ImportResult result) {
        // Check JSON body first (most common)
        if (response.isJsonResponse() && response.body != null && !response.body.isEmpty()) {
            String jsonPath = findTokenInJson(response.body);
            if (jsonPath != null) {
                result.extractionSource = TokenExtractionConfig.SourceType.JSON_BODY;
                result.extractionPath = jsonPath;
                result.detectedTokenPreview = extractTokenPreview(response.body, jsonPath);
                return;
            }
        }

        // Check for token in headers
        for (Map.Entry<String, String> header : response.headers.entrySet()) {
            String name = header.getKey().toLowerCase();
            String value = header.getValue();

            // Check for Authorization-style headers in response
            if (name.contains("token") || name.contains("auth")) {
                result.extractionSource = TokenExtractionConfig.SourceType.HEADER;
                result.extractionPath = header.getKey();
                result.detectedTokenPreview = truncateForPreview(value);
                return;
            }
        }

        // Check for token cookies
        String setCookie = response.headers.getOrDefault("Set-Cookie",
                response.headers.getOrDefault("set-cookie", ""));
        if (!setCookie.isEmpty()) {
            // Look for common token cookie names
            for (String tokenName : new String[]{"token", "session", "auth", "jwt", "access"}) {
                if (setCookie.toLowerCase().contains(tokenName)) {
                    result.extractionSource = TokenExtractionConfig.SourceType.COOKIE;
                    // Extract cookie name
                    Pattern pattern = Pattern.compile("([^=;]+)=([^;]+)");
                    Matcher matcher = pattern.matcher(setCookie);
                    if (matcher.find()) {
                        result.extractionPath = matcher.group(1).trim();
                        result.detectedTokenPreview = truncateForPreview(matcher.group(2));
                    }
                    return;
                }
            }
        }
    }

    /**
     * Find a token field in JSON body and return its path.
     */
    private static String findTokenInJson(String json) {
        // Simple pattern matching for common token fields
        // First try top-level fields
        for (String field : TOKEN_FIELDS) {
            Pattern pattern = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(json);
            if (matcher.find()) {
                return field;
            }
        }

        // Try nested in common structures like "data.access_token" or "result.token"
        String[] prefixes = {"data", "result", "response", "body", "payload"};
        for (String prefix : prefixes) {
            for (String field : TOKEN_FIELDS) {
                Pattern pattern = Pattern.compile("\"" + prefix + "\"\\s*:\\s*\\{[^}]*\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = pattern.matcher(json);
                if (matcher.find()) {
                    return prefix + "." + field;
                }
            }
        }

        return null;
    }

    /**
     * Extract token value preview from JSON.
     */
    private static String extractTokenPreview(String json, String path) {
        String[] parts = path.split("\\.");
        String field = parts[parts.length - 1];

        Pattern pattern = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return truncateForPreview(matcher.group(1));
        }
        return null;
    }

    /**
     * Truncate a string for preview display.
     */
    private static String truncateForPreview(String value) {
        if (value == null) {
            return null;
        }
        if (value.length() <= 30) {
            return value;
        }
        return value.substring(0, 30) + "...";
    }

    /**
     * Result of analyzing request/response for import.
     */
    public static class ImportResult {
        // Suggested URL pattern for matching
        public String suggestedUrlPattern = "";

        // Login request configuration
        public String loginUrl = "";
        public String method = "POST";
        public String contentType = "";
        public String loginBody = "";

        // Extra headers to send with login request
        public Map<String, String> extraHeaders = new LinkedHashMap<>();

        // Auth analysis
        public String authType = "";  // "Basic" or "Bearer"
        public String decodedBasicAuth = "";  // Decoded basic auth (client_id:client_secret)

        // Credential detection
        public boolean hasCredentialsInBody = false;
        public String credentialFormat = "";  // "JSON" or "Form"
        public String oauthGrantType = "";  // e.g., "client_credentials"

        // Token extraction suggestion
        public TokenExtractionConfig.SourceType extractionSource = TokenExtractionConfig.SourceType.JSON_BODY;
        public String extractionPath = "";  // JSON path or header/cookie name
        public String detectedTokenPreview = "";  // First 30 chars of detected token

        /**
         * Check if analysis found useful configuration.
         */
        public boolean hasValidConfig() {
            return !loginUrl.isEmpty() && !method.isEmpty();
        }

        /**
         * Check if token extraction was configured.
         */
        public boolean hasTokenExtraction() {
            return extractionPath != null && !extractionPath.isEmpty();
        }

        /**
         * Get a summary of the analysis for display.
         */
        public String getSummary() {
            StringBuilder sb = new StringBuilder();

            if (!loginUrl.isEmpty()) {
                sb.append("Login URL: ").append(loginUrl).append("\n");
            }
            if (!method.isEmpty()) {
                sb.append("Method: ").append(method);
                if (!contentType.isEmpty()) {
                    sb.append(", Content-Type: ").append(contentType);
                }
                sb.append("\n");
            }
            if (!extraHeaders.isEmpty()) {
                sb.append("Extra headers: ");
                for (String key : extraHeaders.keySet()) {
                    sb.append(key);
                    if (key.equalsIgnoreCase("Authorization")) {
                        sb.append(" (").append(authType).append(")");
                    }
                    sb.append(" ");
                }
                sb.append("\n");
            }
            if (!oauthGrantType.isEmpty()) {
                sb.append("OAuth grant type: ").append(oauthGrantType).append("\n");
            }
            if (hasTokenExtraction()) {
                sb.append("Token found: ").append(extractionSource);
                sb.append(" -> ").append(extractionPath);
                if (detectedTokenPreview != null && !detectedTokenPreview.isEmpty()) {
                    sb.append(" (").append(detectedTokenPreview).append(")");
                }
                sb.append("\n");
            }

            return sb.toString();
        }
    }
}

package authomatic.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses raw HTTP request and response text into structured objects.
 */
public class HttpParser {

    /**
     * Parse raw HTTP request text.
     *
     * @param raw The raw HTTP request string
     * @return ParsedRequest object, or null if parsing fails
     */
    public static ParsedRequest parseRequest(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }

        try {
            ParsedRequest request = new ParsedRequest();
            String[] lines = raw.split("\r?\n");

            if (lines.length == 0) {
                return null;
            }

            // Parse request line: METHOD PATH HTTP/VERSION
            String requestLine = lines[0].trim();
            String[] requestParts = requestLine.split("\\s+");
            if (requestParts.length < 2) {
                return null;
            }

            request.method = requestParts[0];
            request.path = requestParts[1];
            request.httpVersion = requestParts.length > 2 ? requestParts[2] : "HTTP/1.1";

            // Parse headers until empty line
            int bodyStartIndex = -1;
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];

                // Empty line signals start of body
                if (line.trim().isEmpty()) {
                    bodyStartIndex = i + 1;
                    break;
                }

                // Parse header
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String name = line.substring(0, colonIndex).trim();
                    String value = line.substring(colonIndex + 1).trim();
                    request.headers.put(name, value);
                }
            }

            // Parse body if present
            if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
                StringBuilder body = new StringBuilder();
                for (int i = bodyStartIndex; i < lines.length; i++) {
                    if (body.length() > 0) {
                        body.append("\n");
                    }
                    body.append(lines[i]);
                }
                request.body = body.toString().trim();
            }

            return request;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse raw HTTP response text.
     *
     * @param raw The raw HTTP response string
     * @return ParsedResponse object, or null if parsing fails
     */
    public static ParsedResponse parseResponse(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }

        try {
            ParsedResponse response = new ParsedResponse();
            String[] lines = raw.split("\r?\n");

            if (lines.length == 0) {
                return null;
            }

            // Parse status line: HTTP/VERSION STATUS_CODE STATUS_TEXT
            String statusLine = lines[0].trim();
            String[] statusParts = statusLine.split("\\s+", 3);
            if (statusParts.length < 2) {
                return null;
            }

            response.httpVersion = statusParts[0];
            response.statusCode = Integer.parseInt(statusParts[1]);
            response.statusText = statusParts.length > 2 ? statusParts[2] : "";

            // Parse headers until empty line
            int bodyStartIndex = -1;
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];

                // Empty line signals start of body
                if (line.trim().isEmpty()) {
                    bodyStartIndex = i + 1;
                    break;
                }

                // Parse header
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String name = line.substring(0, colonIndex).trim();
                    String value = line.substring(colonIndex + 1).trim();
                    response.headers.put(name, value);

                    // Track Set-Cookie headers separately (case-insensitive)
                    if (name.equalsIgnoreCase("Set-Cookie")) {
                        response.setCookies.add(value);
                    }
                }
            }

            // Parse body if present
            if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
                StringBuilder body = new StringBuilder();
                for (int i = bodyStartIndex; i < lines.length; i++) {
                    if (body.length() > 0) {
                        body.append("\n");
                    }
                    body.append(lines[i]);
                }
                response.body = body.toString().trim();
            }

            return response;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Represents a parsed HTTP request.
     */
    public static class ParsedRequest {
        public String method = "";
        public String path = "";
        public String httpVersion = "";
        public Map<String, String> headers = new LinkedHashMap<>();
        public String body = "";

        /**
         * Gets the Host header value.
         */
        public String getHost() {
            return headers.getOrDefault("Host", headers.getOrDefault("host", ""));
        }

        /**
         * Gets the Content-Type header value.
         */
        public String getContentType() {
            return headers.getOrDefault("Content-Type", headers.getOrDefault("content-type", ""));
        }

        /**
         * Gets the Authorization header value.
         */
        public String getAuthorization() {
            return headers.getOrDefault("Authorization", headers.getOrDefault("authorization", ""));
        }

        /**
         * Builds the full URL from Host header and path.
         * Assumes HTTPS by default.
         */
        public String buildFullUrl() {
            String host = getHost();
            if (host.isEmpty()) {
                return path;
            }
            String scheme = "https://";
            return scheme + host + path;
        }

        @Override
        public String toString() {
            return method + " " + path + " " + httpVersion;
        }
    }

    /**
     * Represents a parsed HTTP response.
     */
    public static class ParsedResponse {
        public String httpVersion = "";
        public int statusCode = 0;
        public String statusText = "";
        public Map<String, String> headers = new LinkedHashMap<>();
        public List<String> setCookies = new ArrayList<>();
        public String body = "";

        /**
         * Gets the Content-Type header value.
         */
        public String getContentType() {
            return headers.getOrDefault("Content-Type", headers.getOrDefault("content-type", ""));
        }

        /**
         * Checks if this is a successful response (2xx status).
         */
        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }

        /**
         * Checks if the response body appears to be JSON.
         */
        public boolean isJsonResponse() {
            String contentType = getContentType().toLowerCase();
            return contentType.contains("application/json") ||
                   (body != null && body.trim().startsWith("{"));
        }

        @Override
        public String toString() {
            return httpVersion + " " + statusCode + " " + statusText;
        }
    }
}

package authomatic.config;

import java.util.HashMap;
import java.util.Map;

/**
 * Per-host authentication configuration.
 */
public class HostConfig {

    private boolean enabled = true;
    private String urlPattern = "";       // e.g., "api.example.com/**" or "*.example.com/api/*"
    private String loginUrl = "";
    private String loginMethod = "POST";
    private String contentType = "application/json";
    private String loginBody = "";        // With ${username} and ${password} placeholders
    private String username = "";
    private String password = "";
    private Map<String, String> extraHeaders = new HashMap<>();  // Additional headers for login request
    private TokenExtractionConfig tokenExtraction = new TokenExtractionConfig();
    private TokenInjectionConfig tokenInjection = new TokenInjectionConfig();
    private String rawRequest = "";
    private String rawResponse = "";

    public HostConfig() {
    }

    public HostConfig(String urlPattern) {
        this.urlPattern = urlPattern;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @deprecated Use getUrlPattern() instead
     */
    @Deprecated
    public String getHostPattern() {
        return urlPattern;
    }

    /**
     * @deprecated Use setUrlPattern() instead
     */
    @Deprecated
    public void setHostPattern(String hostPattern) {
        this.urlPattern = hostPattern;
    }

    public String getUrlPattern() {
        return urlPattern;
    }

    public void setUrlPattern(String urlPattern) {
        this.urlPattern = urlPattern;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLoginMethod() {
        return loginMethod;
    }

    public void setLoginMethod(String loginMethod) {
        this.loginMethod = loginMethod;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getLoginBody() {
        return loginBody;
    }

    public void setLoginBody(String loginBody) {
        this.loginBody = loginBody;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Map<String, String> getExtraHeaders() {
        return extraHeaders;
    }

    public void setExtraHeaders(Map<String, String> extraHeaders) {
        this.extraHeaders = extraHeaders != null ? extraHeaders : new HashMap<>();
    }

    public TokenExtractionConfig getTokenExtraction() {
        return tokenExtraction;
    }

    public void setTokenExtraction(TokenExtractionConfig tokenExtraction) {
        this.tokenExtraction = tokenExtraction;
    }

    public TokenInjectionConfig getTokenInjection() {
        return tokenInjection;
    }

    public void setTokenInjection(TokenInjectionConfig tokenInjection) {
        this.tokenInjection = tokenInjection;
    }

    public String getRawRequest() {
        return rawRequest;
    }

    public void setRawRequest(String rawRequest) {
        this.rawRequest = rawRequest != null ? rawRequest : "";
    }

    public String getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(String rawResponse) {
        this.rawResponse = rawResponse != null ? rawResponse : "";
    }

    /**
     * Checks if the given host matches this configuration's URL pattern.
     * Supports wildcard patterns like "*.example.com".
     * For backwards compatibility, also matches host-only patterns.
     * @deprecated Use matchesUrl(host, path) instead
     */
    @Deprecated
    public boolean matchesHost(String host) {
        return matchesUrl(host, "/");
    }

    /**
     * Checks if the given URL (host + path) matches this configuration's URL pattern.
     *
     * Pattern syntax:
     * - host.com/path/* - matches host and path prefix
     * - *.example.com/api/* - wildcard host with path prefix
     * - host.com/** - matches any path on host
     * - host.com (legacy) - matches any path on host
     */
    public boolean matchesUrl(String host, String path) {
        if (urlPattern == null || urlPattern.isEmpty()) {
            return false;
        }

        // Normalize path
        if (path == null || path.isEmpty()) {
            path = "/";
        }

        // Parse pattern into host and path parts
        String patternHost;
        String patternPath;
        int slashIndex = urlPattern.indexOf('/');
        if (slashIndex > 0) {
            patternHost = urlPattern.substring(0, slashIndex);
            patternPath = urlPattern.substring(slashIndex);
        } else {
            // Legacy host-only pattern
            patternHost = urlPattern;
            patternPath = "/**";  // Match any path
        }

        // Match host part
        if (!matchesHostPart(host, patternHost)) {
            return false;
        }

        // Match path part
        return matchesPathPart(path, patternPath);
    }

    /**
     * Match host against pattern host.
     * Supports wildcards like *.example.com
     */
    private boolean matchesHostPart(String host, String patternHost) {
        if (patternHost.startsWith("*.")) {
            String suffix = patternHost.substring(1);  // ".example.com"
            return host.endsWith(suffix) || host.equals(patternHost.substring(2));
        }
        return host.equalsIgnoreCase(patternHost);
    }

    /**
     * Match path against pattern path.
     * Supports wildcards:
     * - /** matches any path
     * - /api/* matches /api/ and /api/anything (but not /api/a/b)
     * - /api/** matches /api/ and any subpath
     */
    private boolean matchesPathPart(String path, String patternPath) {
        // Handle /** (match everything)
        if (patternPath.equals("/**")) {
            return true;
        }

        // Handle /* at the end (single level wildcard)
        if (patternPath.endsWith("/*")) {
            String prefix = patternPath.substring(0, patternPath.length() - 2);
            if (!path.startsWith(prefix)) {
                return false;
            }
            // Check that there's at most one more path segment
            String remainder = path.substring(prefix.length());
            if (remainder.isEmpty() || remainder.equals("/")) {
                return true;
            }
            // Remove leading slash and check for more slashes
            if (remainder.startsWith("/")) {
                remainder = remainder.substring(1);
            }
            return !remainder.contains("/");
        }

        // Handle /** at the end (multi-level wildcard)
        if (patternPath.endsWith("/**")) {
            String prefix = patternPath.substring(0, patternPath.length() - 3);
            return path.startsWith(prefix);
        }

        // Exact match
        return path.equals(patternPath);
    }

    /**
     * Builds the login request body with credentials substituted.
     */
    public String buildLoginBody() {
        if (loginBody == null || loginBody.isEmpty()) {
            return "";
        }
        return loginBody
                .replace("${username}", username != null ? username : "")
                .replace("${password}", password != null ? password : "");
    }

    public HostConfig copy() {
        HostConfig copy = new HostConfig();
        copy.enabled = this.enabled;
        copy.urlPattern = this.urlPattern;
        copy.loginUrl = this.loginUrl;
        copy.loginMethod = this.loginMethod;
        copy.contentType = this.contentType;
        copy.loginBody = this.loginBody;
        copy.username = this.username;
        copy.password = this.password;
        copy.extraHeaders = new HashMap<>(this.extraHeaders);
        copy.tokenExtraction = this.tokenExtraction.copy();
        copy.tokenInjection = this.tokenInjection.copy();
        copy.rawRequest = this.rawRequest;
        copy.rawResponse = this.rawResponse;
        return copy;
    }

    @Override
    public String toString() {
        return urlPattern + " -> " + loginUrl;
    }
}

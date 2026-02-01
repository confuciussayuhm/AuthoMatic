package authomatic.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import authomatic.config.AuthConfig;
import authomatic.config.HostConfig;
import authomatic.util.HttpParser;
import authomatic.util.Logger;
import authomatic.util.RequestMarker;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Orchestrates the re-authentication flow.
 * Manages token cache, per-host locking, and coordinates login/retry operations.
 */
public class AuthManager {

    private final MontoyaApi api;
    private final AuthConfig config;
    private final Logger logger;
    private final TokenExtractor tokenExtractor;
    private final TokenInjector tokenInjector;
    private final RateLimiter rateLimiter;

    // Token cache: host -> extracted token
    private final Map<String, TokenExtractor.ExtractedToken> tokenCache = new ConcurrentHashMap<>();

    // Per-host locks to serialize login attempts
    private final Map<String, Lock> hostLocks = new ConcurrentHashMap<>();

    public AuthManager(MontoyaApi api, AuthConfig config, Logger logger) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.tokenExtractor = new TokenExtractor(logger);
        this.tokenInjector = new TokenInjector(logger);
        this.rateLimiter = new RateLimiter(config.getRateLimitIntervalMs());
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    /**
     * Handles a 401 response by attempting re-authentication.
     * Returns the successful retry response, or null if re-auth failed.
     */
    public HttpResponse handleUnauthorized(HttpRequest originalRequest, HttpResponse originalResponse) {
        String host = originalRequest.httpService().host();
        String path = originalRequest.path();

        // Find config for this URL (host + path)
        HostConfig hostConfig = config.findConfigForUrl(host, path);
        if (hostConfig == null) {
            logger.debug("No configuration found for URL: " + host + path);
            return null;
        }

        // Acquire per-host lock
        Lock lock = hostLocks.computeIfAbsent(host, k -> new ReentrantLock());
        lock.lock();
        try {
            return doReauthentication(originalRequest, hostConfig, host);
        } finally {
            lock.unlock();
        }
    }

    private HttpResponse doReauthentication(HttpRequest originalRequest, HostConfig hostConfig, String host) {
        // Check rate limiter
        if (!rateLimiter.isAllowed(host)) {
            long waitMs = rateLimiter.getRemainingWaitMs(host);
            logger.warn("Rate limited for host " + host + ", wait " + waitMs + "ms");
            return null;
        }

        // Try cached token first (might have been refreshed by another thread)
        TokenExtractor.ExtractedToken cachedToken = tokenCache.get(host);
        if (cachedToken != null) {
            logger.debug("Trying cached token for " + host);
            HttpResponse retryResponse = retryWithToken(originalRequest, cachedToken, hostConfig);
            if (retryResponse != null && retryResponse.statusCode() != 401) {
                logger.info("Retry with cached token succeeded: " + retryResponse.statusCode());
                return retryResponse;
            }
            // Cached token didn't work, need to re-login
            tokenCache.remove(host);
            logger.debug("Cached token expired, performing login");
        }

        // Perform login
        rateLimiter.recordAttempt(host);
        HttpResponse loginResponse = performLogin(hostConfig);
        if (loginResponse == null) {
            logger.error("Login request failed for " + host);
            return null;
        }

        // Check login success (typically 200, but allow 2xx)
        int statusCode = loginResponse.statusCode();
        if (statusCode < 200 || statusCode >= 300) {
            logger.error("Login failed with status " + statusCode + " for " + host);
            return null;
        }

        // Extract token from login response
        TokenExtractor.ExtractedToken token = tokenExtractor.extract(loginResponse, hostConfig);
        if (token == null) {
            logger.error("Failed to extract token from login response for " + host);
            return null;
        }

        logger.info("Token extracted: " + token.getSourceType() + " (" + token.getSourceName() + ")");

        // Cache the token
        tokenCache.put(host, token);

        // Retry original request with new token
        HttpResponse retryResponse = retryWithToken(originalRequest, token, hostConfig);
        if (retryResponse != null) {
            logger.info("Retry with new token returned: " + retryResponse.statusCode());
        }

        return retryResponse;
    }

    /**
     * Performs the login request as configured.
     */
    private HttpResponse performLogin(HostConfig hostConfig) {
        try {
            HttpRequest loginRequest;
            String rawRequest = hostConfig.getRawRequest();

            if (rawRequest != null && !rawRequest.isEmpty()) {
                // Use captured raw request directly (preserves all headers including Host)
                loginRequest = buildLoginRequestFromRaw(rawRequest, hostConfig);
                if (loginRequest == null) {
                    logger.warn("Failed to parse raw request, falling back to config-based request");
                    loginRequest = buildLoginRequestFromConfig(hostConfig);
                }
            } else {
                // Fallback: reconstruct from config fields (for manual/legacy configs)
                loginRequest = buildLoginRequestFromConfig(hostConfig);
            }

            if (loginRequest == null) {
                logger.error("Failed to build login request");
                return null;
            }

            // Mark the request to prevent loop
            loginRequest = RequestMarker.markRequest(loginRequest);

            // Log the full request for debugging
            logger.debug("Login request: " + loginRequest.method() + " " + loginRequest.path());
            for (burp.api.montoya.http.message.HttpHeader h : loginRequest.headers()) {
                logger.debug("  Request Header: " + h.name() + ": " + h.value());
            }
            String body = loginRequest.bodyToString();
            if (body != null && !body.isEmpty()) {
                logger.debug("  Request Body: " + body);
            }

            // Send the request
            HttpResponse response = api.http().sendRequest(loginRequest).response();

            logger.debug("Login response: " + response.statusCode());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                // Log full response for troubleshooting
                for (burp.api.montoya.http.message.HttpHeader h : response.headers()) {
                    logger.debug("  Response Header: " + h.name() + ": " + h.value());
                }
                String responseBody = response.bodyToString();
                if (responseBody != null && !responseBody.isEmpty()) {
                    logger.debug("  Response Body: " + responseBody);
                }
            }
            return response;

        } catch (Exception e) {
            logger.error("Login request error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Builds login request from the stored raw HTTP request text.
     * Preserves all original headers including Host.
     */
    private HttpRequest buildLoginRequestFromRaw(String rawRequest, HostConfig hostConfig) {
        HttpParser.ParsedRequest parsed = HttpParser.parseRequest(rawRequest);
        if (parsed == null) {
            return null;
        }

        // Determine host, port, and HTTPS from Host header
        String hostHeader = parsed.getHost();
        if (hostHeader == null || hostHeader.isEmpty()) {
            logger.warn("Raw request missing Host header");
            return null;
        }

        // Parse host and port from Host header
        String host;
        int port;
        boolean secure = true; // Default to HTTPS

        int colonIndex = hostHeader.indexOf(':');
        if (colonIndex > 0) {
            host = hostHeader.substring(0, colonIndex);
            port = Integer.parseInt(hostHeader.substring(colonIndex + 1));
            // Port 80 typically means HTTP
            if (port == 80) {
                secure = false;
            }
        } else {
            host = hostHeader;
            port = 443; // Default HTTPS port
        }

        // Build the HttpService
        HttpService service = HttpService.httpService(host, port, secure);

        // Start building the request
        HttpRequest request = HttpRequest.httpRequest()
                .withMethod(parsed.method)
                .withPath(parsed.path)
                .withService(service);

        // Add all original headers (preserves Host and all others)
        for (Map.Entry<String, String> header : parsed.headers.entrySet()) {
            request = request.withAddedHeader(header.getKey(), header.getValue());
        }

        // Substitute credentials in the body
        String body = parsed.body;
        if (body != null && !body.isEmpty()) {
            String username = hostConfig.getUsername();
            String password = hostConfig.getPassword();
            body = body.replace("${username}", username != null ? username : "")
                       .replace("${password}", password != null ? password : "");
            request = request.withBody(body);
        }

        logger.info("Built login request from raw request to " + host + parsed.path);
        return request;
    }

    /**
     * Builds login request from decomposed config fields.
     * Used as fallback for manual/legacy configs without rawRequest.
     */
    private HttpRequest buildLoginRequestFromConfig(HostConfig hostConfig) {
        String loginUrl = hostConfig.getLoginUrl();
        String method = hostConfig.getLoginMethod();
        String contentType = hostConfig.getContentType();
        String body = hostConfig.buildLoginBody();

        logger.info("Building login request from config to " + loginUrl);

        // Build the login request
        HttpRequest loginRequest = HttpRequest.httpRequest()
                .withMethod(method)
                .withPath(extractPath(loginUrl));

        // Set the service (host/port/https)
        HttpService service = parseHttpService(loginUrl);
        loginRequest = loginRequest.withService(service);

        // Add required Host header
        loginRequest = loginRequest.withAddedHeader("Host", service.host());

        // Add content type header if body is present
        if (body != null && !body.isEmpty()) {
            loginRequest = loginRequest
                    .withAddedHeader("Content-Type", contentType)
                    .withBody(body);
        }

        // Add extra headers from config (e.g., Authorization: Basic for OAuth2)
        for (Map.Entry<String, String> header : hostConfig.getExtraHeaders().entrySet()) {
            loginRequest = loginRequest.withAddedHeader(header.getKey(), header.getValue());
        }

        return loginRequest;
    }

    /**
     * Retries the original request with the given token.
     */
    private HttpResponse retryWithToken(HttpRequest originalRequest, TokenExtractor.ExtractedToken token,
                                        HostConfig hostConfig) {
        try {
            // Inject token into request
            HttpRequest modifiedRequest = tokenInjector.inject(originalRequest, token, hostConfig);

            // Mark request to prevent loop
            modifiedRequest = RequestMarker.markRequest(modifiedRequest);

            // Send the request
            HttpResponse response = api.http().sendRequest(modifiedRequest).response();

            return response;

        } catch (Exception e) {
            logger.error("Retry request error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Attempts to inject a cached token into an outgoing request.
     * Returns the modified request if a cached token exists, or null otherwise.
     */
    public HttpRequest injectCachedToken(HttpRequest request, HostConfig hostConfig) {
        String host = request.httpService().host();
        TokenExtractor.ExtractedToken cachedToken = tokenCache.get(host);

        if (cachedToken != null) {
            logger.info("Injecting cached token for " + host);
            return tokenInjector.inject(request, cachedToken, hostConfig);
        }

        return null;
    }

    /**
     * Clears the token cache for a specific host.
     */
    public void clearCache(String host) {
        tokenCache.remove(host);
        logger.debug("Cleared token cache for " + host);
    }

    /**
     * Clears the entire token cache.
     */
    public void clearAllCache() {
        tokenCache.clear();
        logger.info("Cleared all token cache");
    }

    /**
     * Gets the cached token for a specific host.
     * Returns null if no token is cached.
     */
    public TokenExtractor.ExtractedToken getCachedToken(String host) {
        return tokenCache.get(host);
    }

    /**
     * Returns the set of hosts that have cached tokens.
     */
    public Set<String> getCachedHosts() {
        return tokenCache.keySet();
    }

    /**
     * Performs login for the given host configuration and returns the token.
     * This is used for manual/on-demand token acquisition.
     * Returns null if login fails or token cannot be extracted.
     */
    public TokenExtractor.ExtractedToken loginAndGetToken(HostConfig hostConfig) {
        String host = extractHostFromUrl(hostConfig.getLoginUrl());

        // Acquire per-host lock
        Lock lock = hostLocks.computeIfAbsent(host, k -> new ReentrantLock());
        lock.lock();
        try {
            // Check rate limiter
            if (!rateLimiter.isAllowed(host)) {
                long waitMs = rateLimiter.getRemainingWaitMs(host);
                logger.warn("Rate limited for host " + host + ", wait " + waitMs + "ms");
                return null;
            }

            // Perform login
            rateLimiter.recordAttempt(host);
            HttpResponse loginResponse = performLogin(hostConfig);
            if (loginResponse == null) {
                logger.error("Login request failed for " + host);
                return null;
            }

            // Check login success
            int statusCode = loginResponse.statusCode();
            if (statusCode < 200 || statusCode >= 300) {
                logger.error("Login failed with status " + statusCode + " for " + host);
                return null;
            }

            // Extract token
            TokenExtractor.ExtractedToken token = tokenExtractor.extract(loginResponse, hostConfig);
            if (token == null) {
                logger.error("Failed to extract token from login response for " + host);
                return null;
            }

            // Cache the token
            tokenCache.put(host, token);
            logger.info("Token extracted and cached: " + token.getSourceType() + " (" + token.getSourceName() + ")");

            return token;

        } finally {
            lock.unlock();
        }
    }

    /**
     * Extracts the host from a URL string.
     */
    private String extractHostFromUrl(String url) {
        if (url == null || url.isEmpty()) {
            return "";
        }
        String hostPart = url.replaceFirst("^https?://", "");
        int pathIndex = hostPart.indexOf('/');
        if (pathIndex > 0) {
            hostPart = hostPart.substring(0, pathIndex);
        }
        int colonIndex = hostPart.indexOf(':');
        if (colonIndex > 0) {
            return hostPart.substring(0, colonIndex);
        }
        return hostPart;
    }

    /**
     * Parses an HttpService from a URL string.
     */
    private HttpService parseHttpService(String url) {
        boolean secure = url.toLowerCase().startsWith("https://");
        String hostPart = url.replaceFirst("^https?://", "");

        // Remove path
        int pathIndex = hostPart.indexOf('/');
        if (pathIndex > 0) {
            hostPart = hostPart.substring(0, pathIndex);
        }

        // Parse host and port
        String host;
        int port;
        int colonIndex = hostPart.indexOf(':');
        if (colonIndex > 0) {
            host = hostPart.substring(0, colonIndex);
            port = Integer.parseInt(hostPart.substring(colonIndex + 1));
        } else {
            host = hostPart;
            port = secure ? 443 : 80;
        }

        return HttpService.httpService(host, port, secure);
    }

    /**
     * Extracts the path from a URL string.
     */
    private String extractPath(String url) {
        String withoutProtocol = url.replaceFirst("^https?://", "");
        int pathIndex = withoutProtocol.indexOf('/');
        if (pathIndex > 0) {
            return withoutProtocol.substring(pathIndex);
        }
        return "/";
    }

    /**
     * Test method to verify login configuration.
     * Returns a result message.
     */
    public String testLogin(HostConfig hostConfig) {
        try {
            HttpResponse loginResponse = performLogin(hostConfig);
            if (loginResponse == null) {
                return "Login request failed - no response";
            }

            int statusCode = loginResponse.statusCode();
            if (statusCode < 200 || statusCode >= 300) {
                return "Login failed with status " + statusCode;
            }

            TokenExtractor.ExtractedToken token = tokenExtractor.extract(loginResponse, hostConfig);
            if (token == null) {
                return "Login succeeded (HTTP " + statusCode + ") but token extraction failed";
            }

            return "Success! Token extracted from " + token.getSourceType() +
                    " (" + token.getSourceName() + "): " +
                    (token.getValue().length() > 30 ?
                            token.getValue().substring(0, 30) + "..." : token.getValue());

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

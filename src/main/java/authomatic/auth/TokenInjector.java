package authomatic.auth;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import authomatic.config.HostConfig;
import authomatic.config.TokenExtractionConfig.SourceType;
import authomatic.config.TokenInjectionConfig;
import authomatic.config.TokenInjectionConfig.TargetType;
import authomatic.util.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Injects authentication tokens into retry requests.
 * Supports auto-detection (mirrors extraction source) or manual configuration.
 */
public class TokenInjector {

    private final Logger logger;

    public TokenInjector(Logger logger) {
        this.logger = logger;
    }

    /**
     * Injects a token into the request based on host configuration.
     */
    public HttpRequest inject(HttpRequest request, TokenExtractor.ExtractedToken token, HostConfig config) {
        TokenInjectionConfig injectionConfig = config.getTokenInjection();

        if (injectionConfig.isAutoDetect()) {
            return autoInject(request, token);
        } else {
            return manualInject(request, token, injectionConfig);
        }
    }

    /**
     * Auto-injects based on the extraction source:
     * - Token from cookie -> inject as same cookie
     * - Token from header -> inject as same header
     * - Token from JSON body -> inject as Authorization: Bearer
     */
    private HttpRequest autoInject(HttpRequest request, TokenExtractor.ExtractedToken token) {
        SourceType sourceType = token.getSourceType();
        String sourceName = token.getSourceName();
        String value = token.getValue();

        switch (sourceType) {
            case COOKIE:
                logger.debug("Auto-injecting token as cookie: " + sourceName);
                return injectCookie(request, sourceName, value);

            case HEADER:
                logger.debug("Auto-injecting token as header: " + sourceName);
                if (sourceName.equalsIgnoreCase("Authorization")) {
                    // Keep the value as-is if it came from Authorization header
                    return injectHeader(request, sourceName, "Bearer " + value);
                }
                return injectHeader(request, sourceName, value);

            case JSON_BODY:
            default:
                logger.debug("Auto-injecting token as Authorization: Bearer");
                return injectBearerToken(request, value);
        }
    }

    /**
     * Manual injection based on explicit configuration.
     */
    private HttpRequest manualInject(HttpRequest request, TokenExtractor.ExtractedToken token,
                                     TokenInjectionConfig config) {
        TargetType targetType = config.getTargetType();
        String targetName = config.getTargetName();
        String value = token.getValue();

        switch (targetType) {
            case COOKIE:
                logger.debug("Manual injecting token as cookie: " + targetName);
                return injectCookie(request, targetName, value);

            case HEADER:
                logger.debug("Manual injecting token as header: " + targetName);
                return injectHeader(request, targetName, value);

            case AUTHORIZATION_BEARER:
            default:
                logger.debug("Manual injecting token as Authorization: Bearer");
                return injectBearerToken(request, value);
        }
    }

    private HttpRequest injectBearerToken(HttpRequest request, String token) {
        // Remove existing Authorization header and add new one
        HttpRequest modified = request.withRemovedHeader("Authorization");
        return modified.withAddedHeader("Authorization", "Bearer " + token);
    }

    private HttpRequest injectHeader(HttpRequest request, String headerName, String headerValue) {
        // Remove existing header and add new one
        HttpRequest modified = request.withRemovedHeader(headerName);
        return modified.withAddedHeader(headerName, headerValue);
    }

    private HttpRequest injectCookie(HttpRequest request, String cookieName, String cookieValue) {
        // Get existing Cookie header
        String existingCookies = null;
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("Cookie")) {
                existingCookies = header.value();
                break;
            }
        }

        String newCookieHeader;
        if (existingCookies == null || existingCookies.isEmpty()) {
            // No existing cookies, just set the new one
            newCookieHeader = cookieName + "=" + cookieValue;
        } else {
            // Parse existing cookies and replace/add the new one
            newCookieHeader = updateCookieHeader(existingCookies, cookieName, cookieValue);
        }

        // Remove old Cookie header and add the new one
        HttpRequest modified = request.withRemovedHeader("Cookie");
        return modified.withAddedHeader("Cookie", newCookieHeader);
    }

    /**
     * Updates a cookie in the Cookie header, or adds it if not present.
     */
    private String updateCookieHeader(String existingCookies, String cookieName, String cookieValue) {
        List<String> cookies = new ArrayList<>();
        boolean found = false;

        // Parse existing cookies
        String[] parts = existingCookies.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;

            int equalsIndex = trimmed.indexOf('=');
            if (equalsIndex > 0) {
                String name = trimmed.substring(0, equalsIndex).trim();
                if (name.equalsIgnoreCase(cookieName)) {
                    // Replace this cookie
                    cookies.add(cookieName + "=" + cookieValue);
                    found = true;
                } else {
                    cookies.add(trimmed);
                }
            } else {
                cookies.add(trimmed);
            }
        }

        // Add if not found
        if (!found) {
            cookies.add(cookieName + "=" + cookieValue);
        }

        return String.join("; ", cookies);
    }
}

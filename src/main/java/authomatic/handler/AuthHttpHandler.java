package authomatic.handler;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import authomatic.auth.AuthManager;
import authomatic.config.AuthConfig;
import authomatic.config.HostConfig;
import authomatic.util.Logger;
import authomatic.util.RequestMarker;

/**
 * HTTP Handler that intercepts 401 responses and triggers re-authentication.
 */
public class AuthHttpHandler implements HttpHandler {

    private final AuthConfig config;
    private final AuthManager authManager;
    private final Logger logger;

    public AuthHttpHandler(AuthConfig config, AuthManager authManager, Logger logger) {
        this.config = config;
        this.authManager = authManager;
        this.logger = logger;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Check if this is a request we're making (login or retry)
        // These already have the skip marker, just remove it before sending
        if (RequestMarker.isMarked(requestToBeSent)) {
            HttpRequest unmarked = RequestMarker.unmarkRequest(requestToBeSent);
            return RequestToBeSentAction.continueWith(unmarked);
        }

        // Check if this URL is a login URL - if so, mark it to prevent loop
        String url = requestToBeSent.url();
        if (config.isLoginUrl(url)) {
            logger.debug("Marking user's login request to prevent loop: " + url);
            HttpRequest marked = RequestMarker.markRequest(requestToBeSent);
            // Remove the marker immediately so it doesn't appear in the actual request
            return RequestToBeSentAction.continueWith(RequestMarker.unmarkRequest(marked));
        }

        // Skip proactive injection if globally disabled
        if (!config.isGlobalEnabled()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Proactive token injection: check if we have a cached token for this URL
        String host = requestToBeSent.httpService().host();
        String path = requestToBeSent.path();
        HostConfig hostConfig = config.findConfigForUrl(host, path);

        if (hostConfig != null) {
            HttpRequest modified = authManager.injectCachedToken(requestToBeSent, hostConfig);
            if (modified != null) {
                logger.info("Proactively injected cached token for " + host + path);
                return RequestToBeSentAction.continueWith(modified);
            }
        }

        // No cached token or no config - let it through unchanged
        // (401 handler will catch it if needed)
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Check global enabled
        if (!config.isGlobalEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Skip non-401 responses
        if (responseReceived.statusCode() != 401) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpRequest initiatingRequest = responseReceived.initiatingRequest();
        String host = initiatingRequest.httpService().host();
        String path = initiatingRequest.path();

        // Check if this request was marked to skip (login/retry request)
        if (RequestMarker.isMarked(initiatingRequest)) {
            logger.debug("Skipping marked request: " + path);
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Check if URL (host + path) is configured
        HostConfig hostConfig = config.findConfigForUrl(host, path);
        if (hostConfig == null) {
            logger.debug("No config for URL: " + host + path);
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Check if this is a login URL (additional loop prevention)
        String url = initiatingRequest.url();
        if (hostConfig.getLoginUrl() != null && url.contains(hostConfig.getLoginUrl())) {
            logger.debug("Skipping login URL: " + url);
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        logger.info("401 intercepted for " + host + path);

        // Attempt re-authentication
        HttpResponse retryResponse = authManager.handleUnauthorized(initiatingRequest, responseReceived);

        if (retryResponse != null) {
            // Return the successful retry response instead of the 401
            logger.info("Returning retry response: " + retryResponse.statusCode());
            return ResponseReceivedAction.continueWith(retryResponse);
        } else {
            // Re-auth failed, return original 401
            logger.warn("Re-authentication failed, returning original 401");
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}

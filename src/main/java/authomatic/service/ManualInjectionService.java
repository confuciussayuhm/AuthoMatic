package authomatic.service;

import authomatic.auth.AuthManager;
import authomatic.auth.TokenExtractor.ExtractedToken;
import authomatic.config.AuthConfig;
import authomatic.config.HostConfig;
import authomatic.model.InjectionRecord;
import authomatic.util.Logger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Service for manual token injection via context menu.
 * Manages host token status, performs injections, and tracks history.
 */
public class ManualInjectionService {

    private final MontoyaApi api;
    private final AuthConfig config;
    private final AuthManager authManager;
    private final Logger logger;

    private final List<InjectionRecord> injectionHistory = new CopyOnWriteArrayList<>();
    private final List<InjectionListener> listeners = new CopyOnWriteArrayList<>();

    // Token cache for manual injections (separate from AuthManager's automatic cache)
    private final Map<String, ExtractedToken> manualTokenCache = new ConcurrentHashMap<>();

    public ManualInjectionService(MontoyaApi api, AuthConfig config, AuthManager authManager, Logger logger) {
        this.api = api;
        this.config = config;
        this.authManager = authManager;
        this.logger = logger;
    }

    /**
     * Listener interface for injection events.
     */
    public interface InjectionListener {
        void onInjectionPerformed(InjectionRecord record);
    }

    public void addListener(InjectionListener listener) {
        listeners.add(listener);
    }

    public void removeListener(InjectionListener listener) {
        listeners.remove(listener);
    }

    /**
     * Returns list of available hosts with their token cache status.
     */
    public List<HostStatus> getAvailableHosts() {
        List<HostStatus> result = new ArrayList<>();
        for (HostConfig hostConfig : config.getHostConfigs()) {
            if (!hostConfig.isEnabled()) {
                continue;
            }
            String pattern = hostConfig.getUrlPattern();
            ExtractedToken token = getCachedTokenForHost(pattern);
            result.add(new HostStatus(hostConfig, token != null));
        }
        return result;
    }

    /**
     * Gets the cached token for a host pattern, checking both manual cache and AuthManager.
     */
    private ExtractedToken getCachedTokenForHost(String urlPattern) {
        // Check manual cache first
        ExtractedToken token = manualTokenCache.get(urlPattern);
        if (token != null) {
            return token;
        }
        // Check AuthManager cache
        return authManager.getCachedToken(extractHostFromPattern(urlPattern));
    }

    /**
     * Extracts the host portion from a URL pattern.
     */
    private String extractHostFromPattern(String urlPattern) {
        if (urlPattern == null || urlPattern.isEmpty()) {
            return "";
        }
        int slashIndex = urlPattern.indexOf('/');
        if (slashIndex > 0) {
            return urlPattern.substring(0, slashIndex);
        }
        return urlPattern;
    }

    /**
     * Performs token injection, replacing the selected text with the token value.
     * If no token is cached, performs login first.
     *
     * @param requestBytes The current request bytes
     * @param selectionStart Start offset of selection
     * @param selectionEnd End offset of selection
     * @param hostConfig The host configuration to use
     * @param requestUrl The URL of the request being edited (for tracking)
     * @return The modified request bytes, or null if injection failed
     */
    public byte[] injectToken(byte[] requestBytes, int selectionStart, int selectionEnd,
                              HostConfig hostConfig, String requestUrl) {
        String pattern = hostConfig.getUrlPattern();
        ExtractedToken token = getCachedTokenForHost(pattern);

        if (token == null) {
            // Need to login first
            token = triggerLoginAndGetToken(hostConfig);
            if (token == null) {
                logger.error("Failed to obtain token for injection: " + pattern);
                return null;
            }
        }

        return performInjection(requestBytes, selectionStart, selectionEnd, token, hostConfig, requestUrl);
    }

    /**
     * Triggers a login and returns the token.
     */
    public ExtractedToken triggerLoginAndGetToken(HostConfig hostConfig) {
        logger.info("Triggering manual login for: " + hostConfig.getUrlPattern());

        ExtractedToken token = authManager.loginAndGetToken(hostConfig);
        if (token != null) {
            // Cache the token
            manualTokenCache.put(hostConfig.getUrlPattern(), token);
            logger.info("Token obtained and cached for: " + hostConfig.getUrlPattern());
        }
        return token;
    }

    /**
     * Performs the actual injection and records it.
     */
    private byte[] performInjection(byte[] requestBytes, int selectionStart, int selectionEnd,
                                    ExtractedToken token, HostConfig hostConfig, String requestUrl) {
        String fullRequestBefore = new String(requestBytes);
        String originalText = fullRequestBefore.substring(selectionStart, selectionEnd);
        String tokenValue = token.getValue();

        // Build the new request
        byte[] tokenBytes = tokenValue.getBytes();
        byte[] result = new byte[requestBytes.length - (selectionEnd - selectionStart) + tokenBytes.length];

        System.arraycopy(requestBytes, 0, result, 0, selectionStart);
        System.arraycopy(tokenBytes, 0, result, selectionStart, tokenBytes.length);
        System.arraycopy(requestBytes, selectionEnd, result, selectionStart + tokenBytes.length,
                requestBytes.length - selectionEnd);

        String fullRequestAfter = new String(result);

        // Record the injection
        InjectionRecord record = new InjectionRecord(
                requestUrl,
                selectionStart,
                selectionEnd,
                hostConfig.getUrlPattern(),
                originalText,
                tokenValue,
                fullRequestBefore,
                fullRequestAfter
        );

        injectionHistory.add(0, record);  // Add to front (newest first)
        notifyListeners(record);

        logger.info("Token injected: replaced " + originalText.length() + " chars with " +
                tokenValue.length() + " char token");

        return result;
    }

    private void notifyListeners(InjectionRecord record) {
        for (InjectionListener listener : listeners) {
            try {
                listener.onInjectionPerformed(record);
            } catch (Exception e) {
                logger.error("Error notifying injection listener: " + e.getMessage());
            }
        }
    }

    /**
     * Returns the injection history.
     */
    public List<InjectionRecord> getInjectionHistory() {
        return new ArrayList<>(injectionHistory);
    }

    /**
     * Clears the injection history.
     */
    public void clearHistory() {
        injectionHistory.clear();
        logger.info("Injection history cleared");
    }

    /**
     * Clears the manual token cache.
     */
    public void clearCache() {
        manualTokenCache.clear();
        logger.info("Manual token cache cleared");
    }

    /**
     * Status of a host configuration with token availability.
     */
    public static class HostStatus {
        private final HostConfig hostConfig;
        private final boolean hasCachedToken;

        public HostStatus(HostConfig hostConfig, boolean hasCachedToken) {
            this.hostConfig = hostConfig;
            this.hasCachedToken = hasCachedToken;
        }

        public HostConfig getHostConfig() {
            return hostConfig;
        }

        public boolean hasCachedToken() {
            return hasCachedToken;
        }

        public String getDisplayName() {
            String pattern = hostConfig.getUrlPattern();
            if (hasCachedToken) {
                return pattern + " [cached]";
            } else {
                return pattern + " [will login]";
            }
        }
    }
}

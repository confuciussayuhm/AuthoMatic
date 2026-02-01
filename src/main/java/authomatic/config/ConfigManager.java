package authomatic.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import authomatic.util.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages persistence of AuthoMatic configuration using Burp's persistence API.
 */
public class ConfigManager {

    private static final String KEY_GLOBAL_ENABLED = "globalEnabled";
    private static final String KEY_RATE_LIMIT = "rateLimitIntervalMs";
    private static final String KEY_HOST_COUNT = "hostCount";
    private static final String KEY_HOST_PREFIX = "host_";

    private final MontoyaApi api;
    private final Logger logger;
    private AuthConfig config;

    public ConfigManager(MontoyaApi api, Logger logger) {
        this.api = api;
        this.logger = logger;
        this.config = new AuthConfig();
    }

    public AuthConfig getConfig() {
        return config;
    }

    public void load() {
        try {
            PersistedObject data = api.persistence().extensionData();

            Boolean globalEnabled = data.getBoolean(KEY_GLOBAL_ENABLED);
            if (globalEnabled != null) {
                config.setGlobalEnabled(globalEnabled);
            }

            Long rateLimitStr = data.getLong(KEY_RATE_LIMIT);
            if (rateLimitStr != null) {
                config.setRateLimitIntervalMs(rateLimitStr);
            }

            Integer hostCount = data.getInteger(KEY_HOST_COUNT);
            if (hostCount != null && hostCount > 0) {
                List<HostConfig> hosts = new ArrayList<>();
                for (int i = 0; i < hostCount; i++) {
                    HostConfig hostConfig = loadHostConfig(data, KEY_HOST_PREFIX + i);
                    if (hostConfig != null) {
                        hosts.add(hostConfig);
                    }
                }
                config.setHostConfigs(hosts);
            }

            logger.info("Configuration loaded: " + config.getHostConfigs().size() + " host(s)");
        } catch (Exception e) {
            logger.error("Failed to load configuration: " + e.getMessage());
        }
    }

    public void save() {
        try {
            PersistedObject data = api.persistence().extensionData();

            data.setBoolean(KEY_GLOBAL_ENABLED, config.isGlobalEnabled());
            data.setLong(KEY_RATE_LIMIT, config.getRateLimitIntervalMs());
            data.setInteger(KEY_HOST_COUNT, config.getHostConfigs().size());

            for (int i = 0; i < config.getHostConfigs().size(); i++) {
                saveHostConfig(data, KEY_HOST_PREFIX + i, config.getHostConfigs().get(i));
            }

            logger.info("Configuration saved: " + config.getHostConfigs().size() + " host(s)");
        } catch (Exception e) {
            logger.error("Failed to save configuration: " + e.getMessage());
        }
    }

    private HostConfig loadHostConfig(PersistedObject data, String prefix) {
        // Try new urlPattern key first, fall back to old hostPattern for migration
        String urlPattern = data.getString(prefix + ".urlPattern");
        if (urlPattern == null || urlPattern.isEmpty()) {
            // Migration: try old hostPattern key
            urlPattern = data.getString(prefix + ".hostPattern");
        }
        if (urlPattern == null || urlPattern.isEmpty()) {
            return null;
        }

        HostConfig host = new HostConfig();
        host.setUrlPattern(urlPattern);

        Boolean enabled = data.getBoolean(prefix + ".enabled");
        host.setEnabled(enabled != null ? enabled : true);

        String loginUrl = data.getString(prefix + ".loginUrl");
        host.setLoginUrl(loginUrl != null ? loginUrl : "");

        String loginMethod = data.getString(prefix + ".loginMethod");
        host.setLoginMethod(loginMethod != null ? loginMethod : "POST");

        String contentType = data.getString(prefix + ".contentType");
        host.setContentType(contentType != null ? contentType : "application/json");

        String loginBody = data.getString(prefix + ".loginBody");
        host.setLoginBody(loginBody != null ? loginBody : "");

        String username = data.getString(prefix + ".username");
        host.setUsername(username != null ? username : "");

        String password = data.getString(prefix + ".password");
        host.setPassword(password != null ? password : "");

        // Load extra headers
        Map<String, String> extraHeaders = loadExtraHeaders(data, prefix + ".extraHeaders");
        host.setExtraHeaders(extraHeaders);

        // Token extraction
        TokenExtractionConfig extraction = new TokenExtractionConfig();
        Boolean extractionAutoDetect = data.getBoolean(prefix + ".extraction.autoDetect");
        extraction.setAutoDetect(extractionAutoDetect != null ? extractionAutoDetect : true);

        String sourceType = data.getString(prefix + ".extraction.sourceType");
        if (sourceType != null) {
            try {
                extraction.setSourceType(TokenExtractionConfig.SourceType.valueOf(sourceType));
            } catch (IllegalArgumentException ignored) {
            }
        }

        String tokenName = data.getString(prefix + ".extraction.tokenName");
        extraction.setTokenName(tokenName != null ? tokenName : "");

        String jsonPath = data.getString(prefix + ".extraction.jsonPath");
        extraction.setJsonPath(jsonPath != null ? jsonPath : "");

        Integer selectionStart = data.getInteger(prefix + ".extraction.selectionStart");
        extraction.setSelectionStart(selectionStart != null ? selectionStart : -1);

        Integer selectionEnd = data.getInteger(prefix + ".extraction.selectionEnd");
        extraction.setSelectionEnd(selectionEnd != null ? selectionEnd : -1);

        String selectedValue = data.getString(prefix + ".extraction.selectedValue");
        extraction.setSelectedValue(selectedValue != null ? selectedValue : "");

        host.setTokenExtraction(extraction);

        // Token injection
        TokenInjectionConfig injection = new TokenInjectionConfig();
        Boolean injectionAutoDetect = data.getBoolean(prefix + ".injection.autoDetect");
        injection.setAutoDetect(injectionAutoDetect != null ? injectionAutoDetect : true);

        String targetType = data.getString(prefix + ".injection.targetType");
        if (targetType != null) {
            try {
                injection.setTargetType(TokenInjectionConfig.TargetType.valueOf(targetType));
            } catch (IllegalArgumentException ignored) {
            }
        }

        String targetName = data.getString(prefix + ".injection.targetName");
        injection.setTargetName(targetName != null ? targetName : "");

        host.setTokenInjection(injection);

        // Raw request/response
        String rawRequest = data.getString(prefix + ".rawRequest");
        host.setRawRequest(rawRequest != null ? rawRequest : "");

        String rawResponse = data.getString(prefix + ".rawResponse");
        host.setRawResponse(rawResponse != null ? rawResponse : "");

        return host;
    }

    private void saveHostConfig(PersistedObject data, String prefix, HostConfig host) {
        // Save with new urlPattern key (also keep old key for backwards compatibility)
        data.setString(prefix + ".urlPattern", host.getUrlPattern());
        data.setString(prefix + ".hostPattern", host.getUrlPattern());  // Backwards compatibility
        data.setBoolean(prefix + ".enabled", host.isEnabled());
        data.setString(prefix + ".loginUrl", host.getLoginUrl());
        data.setString(prefix + ".loginMethod", host.getLoginMethod());
        data.setString(prefix + ".contentType", host.getContentType());
        data.setString(prefix + ".loginBody", host.getLoginBody());
        data.setString(prefix + ".username", host.getUsername());
        data.setString(prefix + ".password", host.getPassword());

        // Save extra headers
        saveExtraHeaders(data, prefix + ".extraHeaders", host.getExtraHeaders());

        // Token extraction
        TokenExtractionConfig extraction = host.getTokenExtraction();
        data.setBoolean(prefix + ".extraction.autoDetect", extraction.isAutoDetect());
        data.setString(prefix + ".extraction.sourceType", extraction.getSourceType().name());
        data.setString(prefix + ".extraction.tokenName", extraction.getTokenName());
        data.setString(prefix + ".extraction.jsonPath", extraction.getJsonPath());
        data.setInteger(prefix + ".extraction.selectionStart", extraction.getSelectionStart());
        data.setInteger(prefix + ".extraction.selectionEnd", extraction.getSelectionEnd());
        data.setString(prefix + ".extraction.selectedValue", extraction.getSelectedValue());

        // Token injection
        TokenInjectionConfig injection = host.getTokenInjection();
        data.setBoolean(prefix + ".injection.autoDetect", injection.isAutoDetect());
        data.setString(prefix + ".injection.targetType", injection.getTargetType().name());
        data.setString(prefix + ".injection.targetName", injection.getTargetName());

        // Raw request/response
        data.setString(prefix + ".rawRequest", host.getRawRequest());
        data.setString(prefix + ".rawResponse", host.getRawResponse());
    }

    /**
     * Load extra headers from persistence.
     * Headers are stored as count + key/value pairs.
     */
    private Map<String, String> loadExtraHeaders(PersistedObject data, String prefix) {
        Map<String, String> headers = new HashMap<>();

        Integer count = data.getInteger(prefix + ".count");
        if (count != null && count > 0) {
            for (int i = 0; i < count; i++) {
                String key = data.getString(prefix + "." + i + ".key");
                String value = data.getString(prefix + "." + i + ".value");
                if (key != null && !key.isEmpty()) {
                    headers.put(key, value != null ? value : "");
                }
            }
        }

        return headers;
    }

    /**
     * Save extra headers to persistence.
     */
    private void saveExtraHeaders(PersistedObject data, String prefix, Map<String, String> headers) {
        data.setInteger(prefix + ".count", headers.size());

        int i = 0;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            data.setString(prefix + "." + i + ".key", entry.getKey());
            data.setString(prefix + "." + i + ".value", entry.getValue());
            i++;
        }
    }
}

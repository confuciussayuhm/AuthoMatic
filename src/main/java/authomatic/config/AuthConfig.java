package authomatic.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Root configuration for AuthoMatic extension.
 */
public class AuthConfig {

    private boolean globalEnabled = true;
    private long rateLimitIntervalMs = 5000;
    private List<HostConfig> hostConfigs = new ArrayList<>();

    public AuthConfig() {
    }

    public boolean isGlobalEnabled() {
        return globalEnabled;
    }

    public void setGlobalEnabled(boolean globalEnabled) {
        this.globalEnabled = globalEnabled;
    }

    public long getRateLimitIntervalMs() {
        return rateLimitIntervalMs;
    }

    public void setRateLimitIntervalMs(long rateLimitIntervalMs) {
        this.rateLimitIntervalMs = rateLimitIntervalMs;
    }

    public List<HostConfig> getHostConfigs() {
        return hostConfigs;
    }

    public void setHostConfigs(List<HostConfig> hostConfigs) {
        this.hostConfigs = hostConfigs;
    }

    public void addHostConfig(HostConfig config) {
        hostConfigs.add(config);
    }

    public void removeHostConfig(HostConfig config) {
        hostConfigs.remove(config);
    }

    /**
     * Finds the matching host configuration for a given host.
     * Returns null if no matching configuration is found.
     * @deprecated Use findConfigForUrl(host, path) instead
     */
    @Deprecated
    public HostConfig findConfigForHost(String host) {
        return findConfigForUrl(host, "/");
    }

    /**
     * Finds the matching configuration for a given URL (host + path).
     * Returns null if no matching configuration is found.
     * More specific patterns (longer path matches) take precedence.
     */
    public HostConfig findConfigForUrl(String host, String path) {
        HostConfig bestMatch = null;
        int bestSpecificity = -1;

        for (HostConfig config : hostConfigs) {
            if (config.isEnabled() && config.matchesUrl(host, path)) {
                // Calculate specificity based on pattern length and path detail
                int specificity = calculateSpecificity(config.getUrlPattern());
                if (specificity > bestSpecificity) {
                    bestSpecificity = specificity;
                    bestMatch = config;
                }
            }
        }
        return bestMatch;
    }

    /**
     * Calculate pattern specificity for matching priority.
     * More specific patterns (longer, with more path segments) get higher scores.
     */
    private int calculateSpecificity(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return 0;
        }

        int score = 0;

        // Longer patterns are more specific
        score += pattern.length();

        // Patterns with paths are more specific than host-only
        if (pattern.contains("/")) {
            score += 100;
        }

        // Single-level wildcards are more specific than double wildcards
        if (pattern.contains("/**")) {
            score -= 50;
        }

        // Exact host (no wildcard) is more specific
        if (!pattern.startsWith("*.")) {
            score += 50;
        }

        return score;
    }

    /**
     * Checks if a URL is a configured login URL.
     */
    public boolean isLoginUrl(String url) {
        for (HostConfig config : hostConfigs) {
            if (config.getLoginUrl() != null && config.getLoginUrl().equals(url)) {
                return true;
            }
        }
        return false;
    }
}

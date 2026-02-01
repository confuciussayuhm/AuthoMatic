package authomatic.auth;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiter to prevent login spam.
 * Tracks the last login attempt time per host and enforces a minimum interval.
 */
public class RateLimiter {

    private final Map<String, Long> lastLoginAttempts = new ConcurrentHashMap<>();
    private volatile long intervalMs;

    public RateLimiter(long intervalMs) {
        this.intervalMs = intervalMs;
    }

    public void setIntervalMs(long intervalMs) {
        this.intervalMs = intervalMs;
    }

    public long getIntervalMs() {
        return intervalMs;
    }

    /**
     * Checks if a login attempt is allowed for the given host.
     * Returns true if allowed, false if rate limited.
     */
    public boolean isAllowed(String host) {
        long now = System.currentTimeMillis();
        Long lastAttempt = lastLoginAttempts.get(host);

        if (lastAttempt == null) {
            return true;
        }

        return (now - lastAttempt) >= intervalMs;
    }

    /**
     * Records a login attempt for the given host.
     */
    public void recordAttempt(String host) {
        lastLoginAttempts.put(host, System.currentTimeMillis());
    }

    /**
     * Returns the remaining wait time in milliseconds for a host.
     * Returns 0 if no wait is required.
     */
    public long getRemainingWaitMs(String host) {
        Long lastAttempt = lastLoginAttempts.get(host);
        if (lastAttempt == null) {
            return 0;
        }

        long elapsed = System.currentTimeMillis() - lastAttempt;
        long remaining = intervalMs - elapsed;
        return Math.max(0, remaining);
    }

    /**
     * Clears the rate limit record for a specific host.
     */
    public void clearHost(String host) {
        lastLoginAttempts.remove(host);
    }

    /**
     * Clears all rate limit records.
     */
    public void clearAll() {
        lastLoginAttempts.clear();
    }
}

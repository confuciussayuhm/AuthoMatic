package authomatic.model;

import java.time.LocalDateTime;

/**
 * Data class for tracking manual token injections.
 * Stores before/after state for diff view.
 */
public class InjectionRecord {

    private final LocalDateTime timestamp;
    private final String requestUrl;
    private final int selectionStart;
    private final int selectionEnd;
    private final String hostConfigPattern;
    private final String originalText;
    private final String injectedToken;
    private final String fullRequestBefore;
    private final String fullRequestAfter;

    public InjectionRecord(
            String requestUrl,
            int selectionStart,
            int selectionEnd,
            String hostConfigPattern,
            String originalText,
            String injectedToken,
            String fullRequestBefore,
            String fullRequestAfter) {
        this.timestamp = LocalDateTime.now();
        this.requestUrl = requestUrl;
        this.selectionStart = selectionStart;
        this.selectionEnd = selectionEnd;
        this.hostConfigPattern = hostConfigPattern;
        this.originalText = originalText;
        this.injectedToken = injectedToken;
        this.fullRequestBefore = fullRequestBefore;
        this.fullRequestAfter = fullRequestAfter;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public int getSelectionStart() {
        return selectionStart;
    }

    public int getSelectionEnd() {
        return selectionEnd;
    }

    public String getHostConfigPattern() {
        return hostConfigPattern;
    }

    public String getOriginalText() {
        return originalText;
    }

    public String getInjectedToken() {
        return injectedToken;
    }

    public String getFullRequestBefore() {
        return fullRequestBefore;
    }

    public String getFullRequestAfter() {
        return fullRequestAfter;
    }

    /**
     * Returns a truncated preview of the injected token for display in tables.
     */
    public String getTokenPreview() {
        if (injectedToken == null || injectedToken.isEmpty()) {
            return "";
        }
        if (injectedToken.length() <= 30) {
            return injectedToken;
        }
        return injectedToken.substring(0, 27) + "...";
    }
}

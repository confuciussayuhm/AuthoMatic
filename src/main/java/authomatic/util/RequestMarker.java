package authomatic.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

/**
 * Utility for marking requests to prevent infinite loops.
 * Login requests and retry requests are marked with a special header
 * so they won't trigger re-authentication if they fail.
 */
public class RequestMarker {

    public static final String SKIP_HEADER_NAME = "X-AuthoMatic-Skip";
    public static final String SKIP_HEADER_VALUE = "true";

    private RequestMarker() {
    }

    /**
     * Marks a request so it won't be processed by AuthoMatic.
     */
    public static HttpRequest markRequest(HttpRequest request) {
        return request.withAddedHeader(SKIP_HEADER_NAME, SKIP_HEADER_VALUE);
    }

    /**
     * Checks if a request is marked to be skipped.
     */
    public static boolean isMarked(HttpRequest request) {
        List<HttpHeader> headers = request.headers();
        for (HttpHeader header : headers) {
            if (SKIP_HEADER_NAME.equalsIgnoreCase(header.name())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes the skip marker from a request (for clean forwarding).
     */
    public static HttpRequest unmarkRequest(HttpRequest request) {
        return request.withRemovedHeader(SKIP_HEADER_NAME);
    }
}

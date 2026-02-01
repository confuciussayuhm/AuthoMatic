package authomatic.ui;

import authomatic.config.TokenExtractionConfig;

import javax.swing.*;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.text.*;
import java.awt.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Custom JTextPane with persistent highlighting for token selection.
 * Allows users to select text and highlights the selection.
 */
public class SelectableTextPane extends JTextPane {

    private static final Color HIGHLIGHT_COLOR = new Color(255, 255, 150); // Light yellow

    private final Highlighter.HighlightPainter highlightPainter;
    private Object currentHighlight;
    private Consumer<SelectionInfo> onSelectionListener;

    public SelectableTextPane() {
        setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        highlightPainter = new DefaultHighlighter.DefaultHighlightPainter(HIGHLIGHT_COLOR);

        addCaretListener(new CaretListener() {
            @Override
            public void caretUpdate(CaretEvent e) {
                int dot = e.getDot();
                int mark = e.getMark();
                if (dot != mark) {
                    int start = Math.min(dot, mark);
                    int end = Math.max(dot, mark);
                    String selectedText = getSelectedText();
                    if (selectedText != null && !selectedText.isEmpty()) {
                        notifySelection(start, end, selectedText);
                    }
                }
            }
        });
    }

    public void setOnSelectionListener(Consumer<SelectionInfo> listener) {
        this.onSelectionListener = listener;
    }

    /**
     * Set persistent highlight at the given positions.
     */
    public void setHighlight(int start, int end) {
        clearHighlight();
        if (start >= 0 && end > start && end <= getDocument().getLength()) {
            try {
                currentHighlight = getHighlighter().addHighlight(start, end, highlightPainter);
            } catch (BadLocationException ignored) {
            }
        }
    }

    /**
     * Clear the persistent highlight.
     */
    public void clearHighlight() {
        if (currentHighlight != null) {
            getHighlighter().removeHighlight(currentHighlight);
            currentHighlight = null;
        }
    }

    private void notifySelection(int start, int end, String selectedText) {
        if (onSelectionListener == null) {
            return;
        }

        String text = getText();
        SelectionInfo info = analyzeSelection(text, start, end, selectedText);
        onSelectionListener.accept(info);
    }

    /**
     * Analyze the selection to determine source type and path.
     */
    private SelectionInfo analyzeSelection(String text, int start, int end, String selectedText) {
        SelectionInfo info = new SelectionInfo();
        info.start = start;
        info.end = end;
        info.selectedValue = selectedText;

        // Find the blank line separating headers from body
        int headerBodySplit = findHeaderBodySplit(text);

        if (headerBodySplit == -1 || start < headerBodySplit) {
            // Selection is in headers
            String headerSection = headerBodySplit > 0 ? text.substring(0, headerBodySplit) : text;
            analyzeHeaderSelection(headerSection, start, info);
        } else {
            // Selection is in body
            String afterSplit = text.substring(headerBodySplit);
            int leadingWhitespace = 0;
            while (leadingWhitespace < afterSplit.length() &&
                   Character.isWhitespace(afterSplit.charAt(leadingWhitespace))) {
                leadingWhitespace++;
            }
            String bodySection = afterSplit.substring(leadingWhitespace);
            int bodyStart = headerBodySplit + leadingWhitespace;
            analyzeBodySelection(bodySection, start - bodyStart, info);
        }

        return info;
    }

    /**
     * Find the index where headers end and body begins (blank line).
     */
    private int findHeaderBodySplit(String text) {
        // Look for \r\n\r\n or \n\n
        int idx = text.indexOf("\r\n\r\n");
        if (idx != -1) {
            return idx + 4;
        }
        idx = text.indexOf("\n\n");
        if (idx != -1) {
            return idx + 2;
        }
        return -1;
    }

    /**
     * Analyze selection within headers.
     */
    private void analyzeHeaderSelection(String headers, int selectionStart, SelectionInfo info) {
        // Find which line the selection starts on
        String[] lines = headers.split("\\r?\\n");
        int currentPos = 0;

        for (String line : lines) {
            int lineEnd = currentPos + line.length();
            if (selectionStart >= currentPos && selectionStart <= lineEnd) {
                // Selection is on this line
                String lineLower = line.toLowerCase();
                if (lineLower.startsWith("set-cookie:")) {
                    info.sourceType = TokenExtractionConfig.SourceType.COOKIE;
                    info.path = parseCookieName(line);
                } else if (line.contains(":")) {
                    info.sourceType = TokenExtractionConfig.SourceType.HEADER;
                    info.path = line.substring(0, line.indexOf(':')).trim();
                }
                return;
            }
            currentPos = lineEnd + 1; // +1 for newline
        }
    }

    /**
     * Parse cookie name from Set-Cookie header line.
     */
    private String parseCookieName(String line) {
        // Set-Cookie: name=value; ...
        int colonIdx = line.indexOf(':');
        if (colonIdx == -1) return "";

        String value = line.substring(colonIdx + 1).trim();
        int equalsIdx = value.indexOf('=');
        if (equalsIdx == -1) return "";

        return value.substring(0, equalsIdx).trim();
    }

    /**
     * Analyze selection within body (assumed JSON).
     */
    private void analyzeBodySelection(String body, int relativeStart, SelectionInfo info) {
        info.sourceType = TokenExtractionConfig.SourceType.JSON_BODY;
        info.path = findJsonKeyForPosition(body, relativeStart);
    }

    /**
     * Find the JSON key path for a given position in JSON text.
     */
    private String findJsonKeyForPosition(String json, int position) {
        // Simple approach: find the nearest "key": before the position
        // and track nesting

        if (position < 0 || position >= json.length()) {
            return "";
        }

        // Look backwards from position to find the key
        String beforeSelection = json.substring(0, position);

        // Find the last "key": pattern before the selection
        Pattern keyPattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*$");

        // Track nested objects for path building
        java.util.List<String> pathParts = new java.util.ArrayList<>();
        int depth = 0;
        int lastKeyStart = -1;
        String lastKey = null;

        // Simple state machine to track JSON structure
        boolean inString = false;
        boolean escaped = false;
        StringBuilder currentKey = new StringBuilder();
        boolean readingKey = false;
        boolean afterColon = false;

        for (int i = 0; i < position; i++) {
            char c = json.charAt(i);

            if (escaped) {
                escaped = false;
                if (readingKey) currentKey.append(c);
                continue;
            }

            if (c == '\\' && inString) {
                escaped = true;
                if (readingKey) currentKey.append(c);
                continue;
            }

            if (c == '"') {
                if (!inString) {
                    inString = true;
                    if (!afterColon) {
                        readingKey = true;
                        currentKey.setLength(0);
                    }
                } else {
                    inString = false;
                    if (readingKey) {
                        readingKey = false;
                        lastKey = currentKey.toString();
                    }
                }
                continue;
            }

            if (inString) {
                if (readingKey) currentKey.append(c);
                continue;
            }

            if (c == ':') {
                afterColon = true;
                continue;
            }

            if (c == '{' || c == '[') {
                if (afterColon && lastKey != null) {
                    pathParts.add(lastKey);
                }
                depth++;
                afterColon = false;
                lastKey = null;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth >= 0 && !pathParts.isEmpty() && pathParts.size() > depth) {
                    pathParts = new java.util.ArrayList<>(pathParts.subList(0, depth));
                }
                afterColon = false;
            } else if (c == ',') {
                afterColon = false;
                lastKey = null;
            }
        }

        // Build the path
        if (lastKey != null) {
            pathParts.add(lastKey);
        }

        return String.join(".", pathParts);
    }

    /**
     * Information about a text selection.
     */
    public static class SelectionInfo {
        public int start;
        public int end;
        public String selectedValue = "";
        public TokenExtractionConfig.SourceType sourceType = TokenExtractionConfig.SourceType.JSON_BODY;
        public String path = "";

        public String getPreview(int maxLength) {
            if (selectedValue.length() <= maxLength) {
                return selectedValue;
            }
            return selectedValue.substring(0, maxLength - 3) + "...";
        }
    }
}

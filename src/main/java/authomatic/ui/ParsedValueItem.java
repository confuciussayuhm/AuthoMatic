package authomatic.ui;

import authomatic.config.TokenExtractionConfig;

/**
 * Data class representing an item in the token selection dropdown.
 * Can be either a category header (non-selectable) or a selectable value.
 */
public class ParsedValueItem {

    private final TokenExtractionConfig.SourceType sourceType;
    private final String path;
    private final String value;
    private final boolean isCategory;
    private final String displayText;

    /**
     * Create a category header item.
     */
    public static ParsedValueItem category(String categoryName) {
        return new ParsedValueItem(null, categoryName, "", true);
    }

    /**
     * Create a selectable value item.
     */
    public static ParsedValueItem value(TokenExtractionConfig.SourceType sourceType, String path, String value) {
        return new ParsedValueItem(sourceType, path, value, false);
    }

    private ParsedValueItem(TokenExtractionConfig.SourceType sourceType, String path, String value, boolean isCategory) {
        this.sourceType = sourceType;
        this.path = path;
        this.value = value;
        this.isCategory = isCategory;

        if (isCategory) {
            this.displayText = "── " + path + " ──";
        } else {
            String preview = value.length() > 40 ? value.substring(0, 37) + "..." : value;
            this.displayText = path + ": " + preview;
        }
    }

    public TokenExtractionConfig.SourceType getSourceType() {
        return sourceType;
    }

    public String getPath() {
        return path;
    }

    public String getValue() {
        return value;
    }

    public boolean isCategory() {
        return isCategory;
    }

    public String getDisplayText() {
        return displayText;
    }

    @Override
    public String toString() {
        return displayText;
    }
}

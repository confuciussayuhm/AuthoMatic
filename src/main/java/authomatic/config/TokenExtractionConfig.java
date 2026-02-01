package authomatic.config;

/**
 * Configuration for extracting tokens from login responses.
 */
public class TokenExtractionConfig {

    public enum SourceType {
        COOKIE,
        HEADER,
        JSON_BODY
    }

    private boolean autoDetect = true;
    private SourceType sourceType = SourceType.JSON_BODY;
    private String tokenName = "";  // Cookie or header name
    private String jsonPath = "";   // e.g., "data.access_token"
    private int selectionStart = -1;
    private int selectionEnd = -1;
    private String selectedValue = "";

    public TokenExtractionConfig() {
    }

    public TokenExtractionConfig(boolean autoDetect, SourceType sourceType, String tokenName, String jsonPath) {
        this.autoDetect = autoDetect;
        this.sourceType = sourceType;
        this.tokenName = tokenName;
        this.jsonPath = jsonPath;
    }

    public boolean isAutoDetect() {
        return autoDetect;
    }

    public void setAutoDetect(boolean autoDetect) {
        this.autoDetect = autoDetect;
    }

    public SourceType getSourceType() {
        return sourceType;
    }

    public void setSourceType(SourceType sourceType) {
        this.sourceType = sourceType;
    }

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public String getJsonPath() {
        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {
        this.jsonPath = jsonPath;
    }

    public int getSelectionStart() {
        return selectionStart;
    }

    public void setSelectionStart(int selectionStart) {
        this.selectionStart = selectionStart;
    }

    public int getSelectionEnd() {
        return selectionEnd;
    }

    public void setSelectionEnd(int selectionEnd) {
        this.selectionEnd = selectionEnd;
    }

    public String getSelectedValue() {
        return selectedValue;
    }

    public void setSelectedValue(String selectedValue) {
        this.selectedValue = selectedValue != null ? selectedValue : "";
    }

    public boolean hasSelection() {
        return selectionStart >= 0 && selectionEnd > selectionStart && !selectedValue.isEmpty();
    }

    public TokenExtractionConfig copy() {
        TokenExtractionConfig copy = new TokenExtractionConfig(autoDetect, sourceType, tokenName, jsonPath);
        copy.selectionStart = this.selectionStart;
        copy.selectionEnd = this.selectionEnd;
        copy.selectedValue = this.selectedValue;
        return copy;
    }
}

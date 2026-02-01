package authomatic.config;

/**
 * Configuration for injecting tokens into retry requests.
 */
public class TokenInjectionConfig {

    public enum TargetType {
        COOKIE,
        HEADER,
        AUTHORIZATION_BEARER
    }

    private boolean autoDetect = true;
    private TargetType targetType = TargetType.AUTHORIZATION_BEARER;
    private String targetName = "";  // Cookie or header name (empty for Bearer)

    public TokenInjectionConfig() {
    }

    public TokenInjectionConfig(boolean autoDetect, TargetType targetType, String targetName) {
        this.autoDetect = autoDetect;
        this.targetType = targetType;
        this.targetName = targetName;
    }

    public boolean isAutoDetect() {
        return autoDetect;
    }

    public void setAutoDetect(boolean autoDetect) {
        this.autoDetect = autoDetect;
    }

    public TargetType getTargetType() {
        return targetType;
    }

    public void setTargetType(TargetType targetType) {
        this.targetType = targetType;
    }

    public String getTargetName() {
        return targetName;
    }

    public void setTargetName(String targetName) {
        this.targetName = targetName;
    }

    public TokenInjectionConfig copy() {
        return new TokenInjectionConfig(autoDetect, targetType, targetName);
    }
}

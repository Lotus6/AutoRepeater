package burp.SSRF;


public class SSRFSettingsModel {
    private String ceyeToken;
    private String ceyeDnsLog;
    private boolean activated;

    public SSRFSettingsModel(String ceyeToken, String ceyeDnsLog, boolean activated) {
        this.ceyeToken = ceyeToken;
        this.ceyeDnsLog = ceyeDnsLog;
        this.activated = activated;
    }

    public String getCeyeToken() {
        return ceyeToken;
    }

    public void setCeyeToken(String ceyeToken) {
        this.ceyeToken = ceyeToken;
    }

    public String getCeyeDnsLog() {
        return ceyeDnsLog;
    }

    public void setCeyeDnsLog(String ceyeDnsLog) {
        this.ceyeDnsLog = ceyeDnsLog;
    }

    public boolean isActivated() {
        return activated;
    }

    public void setActivated(boolean activated) {
        this.activated = activated;
    }
}

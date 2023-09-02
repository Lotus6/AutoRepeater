package burp.Sqli;

public class SqliSettingsModel {
    private boolean activated;

    public SqliSettingsModel(boolean activated) {
        this.activated = activated;
    }


    public boolean isActivated() {
        return activated;
    }

    public void setActivated(boolean activated) {
        this.activated = activated;
    }
}

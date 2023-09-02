package burp.Redirect;

/**
 * Author 莲花
 */
public class RedirectSettingsModel {
    private String redirectDomain;
    private boolean activated;

    public RedirectSettingsModel(String redirectDomain,boolean activated) {
        this.redirectDomain = redirectDomain;
        this.activated = activated;
    }

    public String getRedirectDomain() {
        return redirectDomain;
    }

    public void setRedirectDomain(String redirectDomain) {
        this.redirectDomain = redirectDomain;
    }


    public boolean isActivated() {
        return activated;
    }

    public void setActivated(boolean activated) {
        this.activated = activated;
    }
}

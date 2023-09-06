package burp.Redirect;

import burp.SSRF.SSRFSettingsModel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Author 莲花
 */
public class Redirect {
    private JPanel redirectPanel;
    private JTextField redirectTextField;
    private RedirectSettingsModel redirectModel;
    private JToggleButton activatedButton;

    public Redirect(String redirectDomain,boolean activated) {
        redirectModel = new RedirectSettingsModel(redirectDomain,activated);
        createUI();
    }

    public void updateUIFromModel() {
        redirectTextField.setText(redirectModel.getRedirectDomain());
        activatedButton.setSelected(redirectModel.isActivated());
        activatedButton.setText(redirectModel.isActivated() ? "Deactivate" : "Activate");
    }

    public RedirectSettingsModel getSettingsModel() {
        return redirectModel;
    }

    public JPanel getUI() {
        return redirectPanel;
    }

    private void createUI() {
        redirectPanel = new JPanel();
        redirectPanel.setLayout(new BoxLayout(redirectPanel, BoxLayout.Y_AXIS));
        redirectPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 创建一个 JToggleButton 来激活/停用 SSRF
        activatedButton = new JToggleButton("Activate");
        activatedButton.addChangeListener(e -> {
            if (activatedButton.isSelected()) {
                activatedButton.setText("Deactivate");
                // 在这里可以执行激活 SSRF 时的操作
            } else {
                activatedButton.setText("Activate");
                // 在这里可以执行停用 SSRF 时的操作
            }
        });

        // 将 activatedButton 添加到 ssrfPanel
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        c.gridx = 0;
        c.weightx = 1;
        redirectPanel.add(activatedButton, c);

        JPanel ceyeTokenPanel = new JPanel();
        ceyeTokenPanel.setLayout(new BoxLayout(ceyeTokenPanel, BoxLayout.Y_AXIS));
        ceyeTokenPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel ceyeTokenLabel = new JLabel("domain:");
        ceyeTokenPanel.add(ceyeTokenLabel);
        redirectTextField = new JTextField(10);
        ceyeTokenPanel.add(redirectTextField);
        redirectPanel.add(ceyeTokenPanel);

        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        redirectPanel.add(saveButton);

        saveButton.addActionListener(e -> {
            String domain = redirectTextField.getText();
            boolean newActivatedState = activatedButton.isSelected();
            redirectModel.setRedirectDomain(domain);
            redirectModel.setActivated(newActivatedState);
            // ... Rest of the code ...
        });

    }


}
